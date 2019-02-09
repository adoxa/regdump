# Registry Dump

Dump one or more registry hives as text, one line per value.  Normally values
and empty keys are written; use `-v` to only show values, or `-k` to only
show keys (along with the time of last write).

Key names, value names and strings will only use ASCII characters, other
characters will be written as `<XX>` or `<XXXX>`, using the hexadecimal code
of the character.

String types will stop at the first null (or double null, for multi), adding
`<...>` to indicate if there is more non-null data; use `-s` to display
everything (although trailing nulls are still not shown).  Multi-strings will
be separated by `<>`.

If binary data is predominantly ASCII (7 out of 8 bytes, or 3 out of 4 words)
it will be displayed as a string, always showing everything (including trailing
nulls).  If 8-byte data matches a 21st century `FILETIME` it will be shown as
date and time (local), as well as data.

Some non-standard value types are supported.  Types under the `Properties`
key having the high 16 bits set will be treated as a device property type
(`0xFFFF0000 | DEVPROP_TYPE...`) and translated to a corresponding standard
type.  Types under the `DriverPackages` key will mask out the high word,
resulting in a standard type.

Note: assumes the hive and CPU are little-endian.

References:

https://www.codeproject.com/KB/recipes/RegistryDumper.aspx  
https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
