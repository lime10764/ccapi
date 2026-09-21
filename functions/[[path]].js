// Pages 顶层通配路由：捕获所有未命中静态资源的请求
import { handleRequest } from './_lib/core.js'

export async function onRequest(context) {
  const { request } = context
  const resp = await handleRequest(request, context.env, context)
  return resp || context.next()
}

