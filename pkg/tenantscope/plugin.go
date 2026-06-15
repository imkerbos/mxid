package tenantscope

import (
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// Tenanted is the marker interface a model implements to opt INTO automatic
// tenant-isolation by the Plugin. Implementing it is a deliberate, auditable
// signal that "every read/update/delete of this table must be pinned to the
// context's tenant unless an explicit escape is present".
//
// Models WITHOUT this marker are never filtered (global tables: mxid_tenant,
// oidc_keyset; child/join tables that derive tenancy via a parent FK; the
// casbin_rule table which has no Go model at all).
type Tenanted interface {
	// TenantScoped is a no-op marker method. Its presence is the opt-in.
	TenantScoped()
}

// TenantColumned lets a model override the tenant column name (default
// "tenant_id"). Rarely needed.
type TenantColumned interface {
	TenantColumn() string
}

// TenantPredicater lets a model supply a custom WHERE predicate instead of the
// default `tenant_id = ?`. Used for the two ambiguous tables:
//
//   - mxid_app: NULL tenant_id = a globally-shared app, so the predicate is
//     `tenant_id = ? OR tenant_id IS NULL`.
//   - mxid_setting: tenant_id = 0 rows are global defaults, so the predicate is
//     `tenant_id IN (?, 0)`.
//
// The returned query string uses a single `?` placeholder bound to tenantID.
type TenantPredicater interface {
	TenantScopePredicate() (query string, includesGlobal bool)
}

const defaultTenantColumn = "tenant_id"

// Plugin is the gorm plugin that enforces tenant isolation on Query/Update/
// Delete (and stamps tenant_id on Create) for models implementing Tenanted.
type Plugin struct{}

// NewPlugin returns the tenant-isolation gorm plugin.
func NewPlugin() *Plugin { return &Plugin{} }

// Name implements gorm.Plugin.
func (p *Plugin) Name() string { return "mxid:tenantscope" }

// Initialize registers the callbacks. They run BEFORE gorm's own
// query/update/delete processors so the predicate is in the SQL.
func (p *Plugin) Initialize(db *gorm.DB) error {
	if err := db.Callback().Query().Before("gorm:query").Register("mxid:tenantscope:query", p.filter); err != nil {
		return err
	}
	if err := db.Callback().Update().Before("gorm:update").Register("mxid:tenantscope:update", p.filter); err != nil {
		return err
	}
	if err := db.Callback().Delete().Before("gorm:delete").Register("mxid:tenantscope:delete", p.filter); err != nil {
		return err
	}
	if err := db.Callback().Create().Before("gorm:create").Register("mxid:tenantscope:create", p.stamp); err != nil {
		return err
	}
	return nil
}

// tenantInfo resolves whether the statement's model is tenant-scoped and, if
// so, the column and predicate to use. Returns scoped=false for any model that
// does not implement Tenanted or whose schema lacks the tenant column.
func tenantInfo(stmt *gorm.Statement) (scoped bool, column string, custom TenantPredicater) {
	if stmt == nil || stmt.Schema == nil {
		return false, "", nil
	}
	// Resolve a zero value of the model type to test the marker interface.
	model := stmt.Model
	if model == nil {
		model = stmt.Dest
	}
	marker := asTenanted(model)
	if marker == nil {
		// Fall back to a zero value built from the schema's ModelType so that
		// e.g. Find(&[]User{}) (Dest is a slice) still sees the marker.
		if stmt.Schema.ModelType != nil {
			zv := reflect.New(stmt.Schema.ModelType).Interface()
			marker = asTenanted(zv)
		}
	}
	if marker == nil {
		return false, "", nil
	}

	column = defaultTenantColumn
	if tc, ok := marker.(TenantColumned); ok {
		column = tc.TenantColumn()
	}
	// The schema MUST actually carry the column, otherwise we cannot filter.
	if !schemaHasColumn(stmt.Schema, column) {
		return false, "", nil
	}
	cp, _ := marker.(TenantPredicater)
	return true, column, cp
}

func asTenanted(v any) Tenanted {
	if v == nil {
		return nil
	}
	if t, ok := v.(Tenanted); ok {
		return t
	}
	// v may be a pointer to a slice / pointer to struct; reflect to a fresh
	// element so a slice destination still resolves the marker.
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			rv = reflect.New(rv.Type().Elem())
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		elem := rv.Type().Elem()
		for elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		if elem.Kind() == reflect.Struct {
			if t, ok := reflect.New(elem).Interface().(Tenanted); ok {
				return t
			}
		}
	case reflect.Struct:
		if t, ok := rv.Addr().Interface().(Tenanted); ok {
			return t
		}
	}
	return nil
}

func schemaHasColumn(s *schema.Schema, col string) bool {
	for _, f := range s.Fields {
		if f.DBName == col {
			return true
		}
	}
	return false
}

// filter injects the tenant predicate into Query/Update/Delete statements.
func (p *Plugin) filter(db *gorm.DB) {
	if db.Statement == nil || db.Error != nil {
		return
	}
	scoped, column, custom := tenantInfo(db.Statement)
	if !scoped {
		return // global model / join table / no tenant column — never filtered
	}

	scope, ok := From(db.Statement.Context)

	// Explicit escapes: background/system jobs and verified cross-tenant reads.
	if ok && (scope.System || scope.CrossTenant) {
		return
	}

	// Fail-closed: a tenant-scoped model with no usable scope must NOT run
	// unscoped. Erroring is the safest outcome — it forces the caller to plumb
	// a scope (or an explicit escape) rather than silently leaking rows.
	if !ok || scope.TenantID <= 0 {
		_ = db.AddError(ErrNoTenantScope)
		return
	}

	table := db.Statement.Table
	if custom != nil {
		query, _ := custom.TenantScopePredicate()
		db.Statement.AddClause(clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: query, Vars: []any{scope.TenantID}},
		}})
		return
	}

	col := clause.Column{Name: column}
	if table != "" {
		col.Table = table
	}
	db.Statement.AddClause(clause.Where{Exprs: []clause.Expression{
		clause.Eq{Column: col, Value: scope.TenantID},
	}})
}

// stamp sets tenant_id on Create when the caller left it zero, so inserts can't
// accidentally land in tenant 0. It NEVER overrides an explicitly-set tenant
// (the model already carried one) and skips system/cross-tenant contexts.
func (p *Plugin) stamp(db *gorm.DB) {
	if db.Statement == nil || db.Error != nil {
		return
	}
	scoped, column, _ := tenantInfo(db.Statement)
	if !scoped {
		return
	}
	scope, ok := From(db.Statement.Context)
	if !ok || scope.System || scope.CrossTenant || scope.TenantID <= 0 {
		// No usable tenant to stamp; leave the row as-is. (Create is not the
		// IDOR surface — reads/updates/deletes are — so we do not fail-closed
		// here, to avoid breaking seeds that set tenant_id explicitly.)
		return
	}
	field := db.Statement.Schema.LookUpField(column)
	if field == nil {
		return
	}
	// Never stamp a NULLABLE tenant column (Go pointer type, e.g. mxid_app's
	// *int64). For those, a NULL is a MEANINGFUL value (a globally-shared
	// row), so inventing a tenant on Create would silently convert a shared
	// row into a tenant-owned one. Such models set tenant_id explicitly.
	if field.FieldType.Kind() == reflect.Ptr {
		return
	}
	stampValue(db, field, scope.TenantID)
}

// stampValue sets the tenant field on the create destination(s) only where it
// is currently the zero value, so an explicitly-provided tenant_id wins.
func stampValue(db *gorm.DB, field *schema.Field, tenantID int64) {
	rv := db.Statement.ReflectValue
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			stampOne(db, field, rv.Index(i), tenantID)
		}
	case reflect.Struct:
		stampOne(db, field, rv, tenantID)
	}
}

func stampOne(db *gorm.DB, field *schema.Field, elem reflect.Value, tenantID int64) {
	for elem.Kind() == reflect.Ptr {
		if elem.IsNil() {
			return
		}
		elem = elem.Elem()
	}
	if !elem.CanAddr() {
		return
	}
	// Only stamp when the tenant field is still the zero value, so an
	// explicitly-provided tenant_id always wins. (Pointer/nullable tenant
	// columns are excluded earlier in stamp().)
	if _, isZero := field.ValueOf(db.Statement.Context, elem); !isZero {
		return
	}
	_ = field.Set(db.Statement.Context, elem, tenantID)
}
