import axios from 'axios'
import type { ApiResponse } from '../types'

// Bootstrap info needed before login: branding + which auth methods to
// render + i18n defaults. Lives at the root namespace because the login
// page renders BEFORE any session cookie exists.
export interface Bootstrap {
  branding: {
    product_name: string
    logo_url: string
    primary_color: string
    login_page_title: string
    login_footer_html: string
    custom_css: string
  }
  login_methods: {
    password: boolean
    sms_otp: boolean
    email_magic_link: boolean
    external_idp_first: boolean
  }
  localization: {
    default_language: string
    default_timezone: string
    date_format: string
  }
}

// Use a plain axios instance — the standard `client` has a Bearer + CSRF
// interceptor stack that's overkill for a public endpoint, and the path
// is root-mounted, not under /api/v1/console.
const root = axios.create({ baseURL: '/' })

export const bootstrapApi = {
  get: () => root.get<ApiResponse<Bootstrap>>('/api/v1/system/bootstrap').then(r => r.data.data),
}
