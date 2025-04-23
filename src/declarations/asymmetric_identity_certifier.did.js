export const idlFactory = ({ IDL }) => {
  const InitArgs = IDL.Record({
    'aes_symmetric_encryption_key_hex' : IDL.Text,
    'controller_principal_id' : IDL.Text,
    'local_mode' : IDL.Bool,
  });
  return IDL.Service({
    'documentation' : IDL.Func([], [IDL.Text], ['query']),
    'get_certified_identity' : IDL.Func([], [IDL.Text], []),
    'get_ecdsa_public_key_hex' : IDL.Func([], [IDL.Text], ['query']),
    'init_ecdsa_key' : IDL.Func([], [IDL.Text], []),
  });
};
export const init = ({ IDL }) => {
  const InitArgs = IDL.Record({
    'aes_symmetric_encryption_key_hex' : IDL.Text,
    'controller_principal_id' : IDL.Text,
    'local_mode' : IDL.Bool,
  });
  return [InitArgs];
};
