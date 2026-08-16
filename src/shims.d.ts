/**
 * acorn / acorn-walk 类型垫片（包本身不携带 d.ts，这里只声明用到的 API）。
 */
declare module 'acorn' {
  export interface Position {
    line: number
    column: number
  }
  export interface NodeLocation {
    start: Position
    end: Position
  }
  export interface Node {
    type: string
    start: number
    end: number
    loc?: NodeLocation | null
    [key: string]: any
  }
  export interface ParseOptions {
    ecmaVersion?: string | number
    sourceType?: 'script' | 'module'
    allowHashBang?: boolean
    allowReturnOutsideFunction?: boolean
    locations?: boolean
    allowAwaitOutsideFunction?: boolean
  }
  export function parse(input: string, options?: ParseOptions): Node
}

declare module 'acorn-walk' {
  import type { Node } from 'acorn'
  export type Visitor = Record<string, (node: any, state: any, type: string) => void>
  export function full(node: Node, callback: (node: any, state: any, type: string) => void, base?: any, state?: any): void
  export function simple(node: Node, visitors: Visitor, base?: any, state?: any): void
  export function ancestor(node: Node, visitors: Visitor, base?: any, state?: any): void
  export const base: Record<string, (node: any, state: any, type: string) => void>
}
