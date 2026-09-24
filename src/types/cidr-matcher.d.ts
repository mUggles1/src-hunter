declare module 'cidr-matcher' {
  export default class CIDRMatcher {
    constructor(cidrs: string[]);
    contains(ip: string): boolean;
    containsAny(ips: string[]): boolean;
  }
}
