import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface InitArgs { 'local_mode' : boolean, 'public_key_hex' : string }
export interface _SERVICE {
  'documentation' : ActorMethod<[], string>,
  'get_certified_identity' : ActorMethod<[], string>,
  'get_ecdsa_public_key_hex' : ActorMethod<[], string>,
  'init_ecdsa_key' : ActorMethod<[], undefined>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
