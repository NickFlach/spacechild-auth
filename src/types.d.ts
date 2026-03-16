/**
 * Type declarations for modules without TypeScript definitions
 */

declare module 'circomlibjs' {
  export function buildPoseidon(): Promise<any>;
}

declare module 'speakeasy' {
  export interface GenerateSecretOptions {
    name: string;
    issuer: string;
    length: number;
  }

  export interface GeneratedSecret {
    base32?: string;
    otpauth_url?: string;
  }

  export interface TotpVerifyOptions {
    secret: string;
    encoding: string;
    token: string;
    window: number;
  }

  export function generateSecret(options: GenerateSecretOptions): GeneratedSecret;
  
  export namespace totp {
    export function verify(options: TotpVerifyOptions): boolean;
  }
}