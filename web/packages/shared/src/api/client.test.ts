// A 204 has no body. The success interceptor used to read `data.code` off the
// resulting empty string, get undefined, and reject — turning every successful
// delete into a "删除失败" toast. Regression guard for the 2026-08-10 incident.

import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { createApiClient } from './client'

let server: http.Server
let baseURL = ''

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/empty-204') {
      res.writeHead(204, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end()
      return
    }
    // A refusal the backend reports INSIDE a 200 envelope — the shape the
    // interceptor exists to catch. HTTP 200, business code 40301.
    if (req.url === '/denied-envelope') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ code: 40301, message: 'forbidden for this target', data: null }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({ code: 0, message: 'ok', data: null }))
  })
  await new Promise<void>((resolve) => server.listen(0, resolve))
  baseURL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('createApiClient response interceptor', () => {
  it('does not reject a 204 with an empty body', async () => {
    const client = createApiClient(baseURL)
    const res = await client.delete('/empty-204')
    expect(res.status).toBe(204)
  })

  it('still resolves a normal 200 envelope', async () => {
    const client = createApiClient(baseURL)
    const res = await client.get('/ok')
    expect(res.data.code).toBe(0)
  })

  // The counterweight to the 204 early-return above, and the one way that fix
  // could itself cause a silent failure: widening "empty body ⇒ success" into
  // "any 200 ⇒ success" would swallow every refusal the backend reports inside
  // a 200 envelope, and the SPA would render a denied write as if it had
  // worked — the same class of lie, pointed the other way.
  it('still rejects a 200 whose envelope carries a business error code', async () => {
    const client = createApiClient(baseURL)
    await expect(client.post('/denied-envelope')).rejects.toMatchObject({
      code: 40301,
      message: 'forbidden for this target',
    })
  })
})
