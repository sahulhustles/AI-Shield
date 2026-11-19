"""Pytest configuration and environment shims for AIShield."""

import typing

# Apply Python 3.14+ PEP 695 compatibility patch for torch_geometric
try:
    import torch_geometric.inspector as _insp

    if not getattr(_insp, "_aishield_patched", False):
        _orig_eval_type = _insp.eval_type

        def _compat_eval_type(value: typing.Any, _globals: typing.Dict[str, typing.Any]) -> typing.Type:
            if isinstance(value, str):
                value = typing.ForwardRef(value)
            try:
                return typing._eval_type(value, _globals, None)
            except TypeError:
                return typing._eval_type(value, _globals, None, ())

        _insp.eval_type = _compat_eval_type
        _insp._aishield_patched = True
except Exception:
    pass
