# 协议配置被静默清空（2026-08-11）

## 摘要

在 console 的 **应用详情 → 协议配置** 里点一次「保存配置」，会删掉该应用 protocol_config 里
这个表单没有字段的所有键。受影响的键包括 `backchannel_logout_uri`（后台通道登出）、
`claim_mappers`、`jwks` / `jwks_uri`、`id_token_ttl`、`rate_limit_per_min`。

全程无报错、无提示，审计里也只有一条泛化的 `update_protocol_config`，不含新旧值。

发现过程：为 Confluence 写 `id_token_userinfo_claims` 的接入文档时，文档第一次把运维引到这个
tab，实测才发现保存动作本身是破坏性的。

## 影响

按严重度：

1. **后台通道登出静默关闭** —— 离职 / JIT 到期不再强制登出下游应用。等保场景下这条最要命。
2. **`private_key_jwt` 客户端认证失败** —— `jwks` / `jwks_uri` 丢失。
3. **scopes 退回默认 `openid profile email`** —— 丢 `groups`（授权映射失效）、丢
   `offline_access`（**refresh token 停发**）。
4. `claim_mappers` 丢失 → 自定义 claim 消失。
5. 每应用限流退回全局默认。

`redirect_uris` 是 `mxid_app` 的独立列，**不在** protocol_config 内，未受影响。

## 根因

四个缺陷叠加，每一个单独看都不致命：

1. **加载即崩。** 加载时把接口返回的每个键都 `String()` 成文本框的值，包括没有对应字段的键。
   `claim_mappers` 是对象数组，转换抛异常 → 整个加载落入 catch → 表单被清空。配了
   claim_mappers 的应用打开就是空表单，且不报错。
2. **保存即替换。** 后端 `UpdateProtocolConfig` 整块替换 JSONB，前端只回传它渲染的键。
   配合上面的空表单，一次保存抹掉全部。
3. **数组存成字符串。** `scopes` / `grant_types` / `response_types` 后端是 `[]string`，
   前端回传逗号拼接的字符串，`json.Unmarshal` 拒绝后静默丢弃。
4. **加载失败仍可保存。** 加载失败后渲染出的是一个空的、可编辑的表单 + 可点的保存按钮 ——
   这一条把任意加载异常放大成了删数据。

第 4 条是真正的放大器：只要它不存在，前三条都只是显示问题。

## 为什么没被发现

- 没有任何检查比对过「console 提供的设置」和「引擎实际读取的键」。同一处还藏着六个纯装饰
  字段（`access_token_lifetime` 等），设置了什么都不会发生，同样多年无人察觉。
- 审计不记录配置的新旧值，所以事后也无从对比。

## 处置

- 前端：未知键透传、列表字段补 coerce、显示转换不再抛异常、**加载失败禁用编辑与保存**。
- 后端：新增 `PATCH /api/v1/console/apps/:id/config` 合并语义（null 删除键），console 改用
  PATCH；`PUT` 保留整体替换。
- 审计：`app.updated` 记录 `config_before` / `config_after` / `changed_keys` —— 从此误操作
  可从审计恢复，不必依赖数据库备份。
- 守卫：`make verify-protocol-fields` 比对 console 字段与引擎结构体 json tag，不匹配即构建失败。
  该守卫的第一版曾对着坏代码报绿（解析器从行中间开始扫，`oidc:` 块整块漏掉），已通过重新引入
  两个历史缺陷验证其确实会失败。

## 排查存量应用

```sql
-- 疑似被洗过配置的 OIDC 应用
SELECT id, code, name,
       protocol_config ? 'backchannel_logout_uri'  AS has_blo,
       jsonb_typeof(protocol_config->'scopes')     AS scopes_type,
       protocol_config ? 'claim_mappers'           AS has_mappers,
       protocol_config
FROM mxid_app
WHERE protocol = 'oidc' AND deleted_at IS NULL
  AND ( jsonb_typeof(protocol_config->'scopes') = 'string'
     OR NOT (protocol_config ? 'scopes')
     OR protocol_config = '{}'::jsonb );
```

`scopes_type = 'string'` 是**铁证** —— 只有经过旧版 console 保存才会出现这种形状。
`protocol_config = '{}'` 需要人工判断（也可能本来就没配过）。

升级到本版之前发生的覆盖，审计里没有旧值，只能从数据库备份恢复。本版之后的每一次修改都带
`config_before`：

```sql
SELECT created_at, actor_name, detail->>'changed_keys', jsonb_pretty(detail->'config_before')
FROM mxid_audit_log
WHERE event_type = 'app.updated' AND detail ? 'config_before' AND resource_id = <app_id>
ORDER BY id DESC;
```
