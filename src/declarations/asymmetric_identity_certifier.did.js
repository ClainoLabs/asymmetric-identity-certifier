export const idlFactory = ({ IDL }) => {
  const InitArgs = IDL.Record({
    'local_mode' : IDL.Bool,
    'public_key_hex' : IDL.Text,
  });
  return IDL.Service({
    'documentation' : IDL.Func([], [IDL.Text], ['query']),
    'get_certified_identity' : IDL.Func([], [IDL.Text], []),
    'get_ecdsa_public_key_hex' : IDL.Func([], [IDL.Text], ['query']),
    'init_ecdsa_key' : IDL.Func([], [], []),
  });
};
export const init = ({ IDL }) => {
  const InitArgs = IDL.Record({
    'local_mode' : IDL.Bool,
    'public_key_hex' : IDL.Text,
  });
  return [InitArgs];
};
