// Pages 顶层通配路由：捕获所有未命中静态资源的请求
import { handleRequest } from './_lib/core.js'

export async function onRequest(context) {
  const { request, env } = context
  const resp = await handleRequest(request, env, context)
  return resp || context.next()  // 非动态路径交回 Pages 静态层（404/静态页）
}
