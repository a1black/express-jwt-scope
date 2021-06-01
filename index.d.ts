import { Handler } from 'express'

declare module 'express-jwt-scope' {
  export function middlewareFactory(): Handler;
}
