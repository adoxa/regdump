/*
  regdump.c - Dump a registry hive.

  Jason Hood, 29 January to 9 February, 2019.
  Based on code by Ladislav Nevery, 2008.

  Dump one or more registry hives as text, one line per value.	Normally values
  and empty keys are written; use "-v" to only show values, or "-k" to only
  show keys (along with the time of last write).

  Key names, value names and strings will only use ASCII characters, other
  characters will be written as "<XX>" or "<XXXX>", using the hexadecimal code
  of the character.

  String types will stop at the first null (or double null, for multi), adding
  "<...>" to indicate if there is more non-null data; use "-s" to display
  everything (although trailing nulls are still not shown).  Multi-strings will
  be separated by "<>".

  If binary data is predominantly ASCII (7 out of 8 bytes, or 3 out of 4 words)
  it will be displayed as a string, always showing everything (including
  trailing nulls).  If 8-byte data matches a 21st century FILETIME it will be
  shown as date and time (local), as well as data.

  Some non-standard value types are supported.	Types under the "Properties"
  key having the high 16 bits set will be treated as a device property type
  (0xFFFF0000 | DEVPROP_TYPE...) and translated to a corresponding standard
  type.  Types under the "DriverPackages" key will mask out the high word,
  resulting in a standard type.

  Note: assumes the hive and CPU are little-endian.

  References:

  https://www.codeproject.com/KB/recipes/RegistryDumper.aspx
  https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
*/

#ifdef _WIN32
# define _CRT_SECURE_NO_WARNINGS
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# define int64_t __int64
# define PRId64 "I64d"
# define PRIX64 "I64X"
#else
# include <inttypes.h>
# include <time.h>
  typedef int  BOOL;
# define TRUE  1
# define FALSE 0
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


BOOL hex_type, only_values, only_keys, all_string, time_sec, time_full;
BOOL big_data;


typedef struct
{
  char signature[4];		// "regf"
  int  primary_sequence_number;
  int  secondary_sequence_number;
  int  last_written_timestamp[2];	// avoid alignment issues with int64_t
  int  major_version;
  int  minor_version;
  int  file_type;
  int  file_format;
  int  root_cell_offset;
  // and more of no interest
} base_block;


typedef struct
{
  int block_size;
  int offsets[1];
} offsets;


typedef struct
{
  int	block_size;
  char	block_type[2];		// "lf" "lh" "li" "ri" "db"
  short count;
  int	offsets[1];
  int	hash;			// only for "lf" "lh", ignored
} list_block;


typedef struct
{
  int	  block_size;
  char	  block_type[2];	// "nk"
  short   flags;
  int64_t timestamp;
  char	  dummya[8];
  int	  subkey_count;
  char	  dummyb[4];
  int	  subkeys;
  char	  dummyc[4];
  int	  value_count;
  int	  values;
  char	  dummyd[28];
  short   len;
  short   du;
  char	  name[1];
} key_block;


typedef struct
{
  int	block_size;
  char	block_type[2];		// "vk"
  short name_len;
  int	size;
  int	offset;
  int	value_type;
  short flags;
  short dummy;
  char	name[1];
} value_block;


#define KEY_COMP_NAME	0x20
#define VALUE_COMP_NAME 0x01


#ifndef _WIN32
enum
{
  REG_NONE,
  REG_SZ,
  REG_EXPAND_SZ,
  REG_BINARY,
  REG_DWORD,
  REG_DWORD_BIG_ENDIAN,
  REG_LINK,
  REG_MULTI_SZ,
  REG_RESOURCE_LIST,
  REG_FULL_RESOURCE_DESCRIPTOR,
  REG_RESOURCE_REQUIREMENTS_LIST,
  REG_QWORD
};
#endif


enum
{
  DEVPROP_TYPE_INT16 = 4,
  DEVPROP_TYPE_UINT16,
  DEVPROP_TYPE_INT32,
  DEVPROP_TYPE_UINT32,
  DEVPROP_TYPE_INT64,
  DEVPROP_TYPE_UINT64,
  DEVPROP_TYPE_FILETIME = 0x10,
  DEVPROP_TYPE_BOOLEAN,
  DEVPROP_TYPE_STRING,
  DEVPROP_TYPE_STRING_LIST = 0x2000 | DEVPROP_TYPE_STRING,
  DEVPROP_TYPE_STRING_INDIRECT = 0x19
};


char* make_name( char* out, char* in, int len, int comp )
{
  int i;

  if (comp)
  {
    unsigned char* uc = (unsigned char*)in;
    for (i = 0; i < len; ++uc, ++i)
    {
      if (*uc >= 32 && *uc < 127)
	*out++ = *uc;
      else
	out += sprintf( out, "<%02X>", *uc );
    }
  }
  else
  {
    unsigned short* us = (unsigned short*)in;
    for (i = 0; i < len / 2; ++us, ++i)
    {
      if (*us >= 32 && *us < 127)
	*out++ = (char)*us;
      else
	out += sprintf( out, "<%0*X>", (*us < 0x100) ? 2 : 4, *us );
    }
  }
  *out = '\0';
  return out;
}


void print_time( int64_t t, BOOL full, BOOL brackets )
{
#ifdef _WIN32
  SYSTEMTIME st;
#else
  time_t secs;
  struct tm* lt;
#endif

  if (brackets)
    putchar( '[' );

#ifdef _WIN32
  FileTimeToSystemTime( (FILETIME*)&t, &st );
  SystemTimeToTzSpecificLocalTime( NULL, &st, &st );
  printf( "%u-%02u-%02u %02u:%02u:%02u",
	  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond );
#else
  // Translate 100-nanosecond intervals from 1601 to seconds from 1970.
  secs = (time_t)(t / 10000000) - 11644473600;
  lt = localtime( &secs );
  printf( "%d-%02d-%02d %02d:%02d:%02d",
	  lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
	  lt->tm_hour, lt->tm_min, lt->tm_sec );
#endif
  if (full)
    printf( ".%07d", (int)(t % 10000000) );

  if (brackets)
  {
    putchar( ']' );
    putchar( ' ' );
  }
}


static char *root, *full;

void walk( char* path, key_block* key )
{
  static BOOL properties, driverpackages;
  offsets* val_list;
  int	size, type;
  char* data;
  char* data_block = NULL;
  BOOL* leave_key = NULL;
  BOOL	empty_key;
  int	bintext;
  int	o, i;

  // Add current key name to printed path.
  *path++ = '/';
  path = make_name( path, key->name, key->len, key->flags & KEY_COMP_NAME );

  if (only_keys)
  {
    print_time( key->timestamp, time_full, TRUE );
    printf( "%s\n", full );
    empty_key = FALSE;
    goto children;
  }

  if (!properties)
  {
    if (key->len == 10 && memcmp( "Properties", key->name, key->len ) == 0)
    {
      properties = TRUE;
      leave_key = &properties;
    }
  }
  if (!driverpackages)
  {
    if (key->len == 14 && memcmp( "DriverPackages", key->name, key->len ) == 0)
    {
      driverpackages = TRUE;
      leave_key = &driverpackages;
    }
  }

  empty_key = (key->value_count == 0);

  // Print all contained values.
  val_list = (offsets*)(key->values + root);
  for (o = 0; o < key->value_count; ++o)
  {
    value_block* val = (value_block*)(val_list->offsets[o] + root);

    *path = '/';
    if (val->name_len == 0)
    {
      path[1] = '@';
      path[2] = '\0';
    }
    else
    {
      make_name( path+1, val->name, val->name_len, val->flags & VALUE_COMP_NAME );
    }

    if (time_sec || time_full)
      print_time( key->timestamp, time_full, TRUE );

    size = val->size & 0x7fffffff;
    if (hex_type)
      printf( "[%08X:%08X] %s = ", val->value_type, size, full );
    else
      printf( "%s [%d:%d] = ", full, val->value_type, size );

    // Data are usually in separate blocks without types, but for small values
    // MS added optimization where if bit 31 is set data are contained within
    // the key itself to save space.
    if (val->size & (1 << 31))
      data = (char*)&val->offset;
    else
    {
      data = val->offset + root + 4;
      if (size > 16344 && big_data && *data == 'd' && data[1] == 'b')
      {
	list_block* item;
	offsets* datalist;
	int left;

	item = (list_block*)(data - 4);
	datalist = (offsets*)(item->offsets[0] + root);
	left = size;
	data = data_block = malloc( size );
	for (i = 0; i < item->count; ++i)
	{
	  memcpy( data, datalist->offsets[i] + root + 4,
		  (left > 16344) ? 16344 : left );
	  data += 16344;
	  left -= 16344;
	}
	data = data_block;
      }
    }

    type = val->value_type;
    if (properties && (type & 0xFFFF0000) == 0xFFFF0000)
    {
      switch (type & 0xFFFF)
      {
	case DEVPROP_TYPE_INT32:
	case DEVPROP_TYPE_UINT32:
	  type = REG_DWORD;
	  break;
	case DEVPROP_TYPE_INT64:
	case DEVPROP_TYPE_UINT64:
	case DEVPROP_TYPE_FILETIME:
	  type = REG_QWORD;
	  break;
	case DEVPROP_TYPE_STRING:
	case DEVPROP_TYPE_STRING_INDIRECT:
	  type = REG_SZ;
	  break;
	case DEVPROP_TYPE_STRING_LIST:
	  type = REG_MULTI_SZ;
	  break;
      }
    }
    else if (driverpackages)
      type &= 0xFFFF;

    // See if binary data is text.
    bintext = 0;
    if ((type == REG_BINARY || type == REG_NONE) && size >= 8)
    {
      int ascii = 0, min = 8;
      if (data[1] == 0 && data[3] == 0)
      {
	unsigned short* us = (unsigned short*)data;
	if (*us >= 32 && *us < 127 &&
	    us[1] >= 32 && us[1] < 127)
	{
	  ascii = 2;
	  for (i = 2; i < size / 2; ++i)
	    if (us[i] >= 32 && us[i] < 127)
	      ++ascii;
	  ascii *= 2;
	  min = 6;
	}
      }
      else if (*data >= 32 && *data < 127 &&
	       data[1] >= 32 && data[1] < 127)
      {
	ascii = 2;
	for (i = 2; i < size; ++i)
	  if (data[i] >= 32 && data[i] < 127)
	    ++ascii;
	min = 7;
      }
      if (ascii * 8 >= size * min)
	bintext = (data[1] == 0) ? 16 : 8;
    }

    if (type == REG_DWORD && size == 4)
    {
      printf( "0x%X (%d)", *(int*)data, *(int*)data );
    }
    else if (properties && size == 1 &&
	     (type == (0xFFFF0000 | DEVPROP_TYPE_BOOLEAN)))
    {
      if (*data == -1)
	printf( "true" );
      else if (*data == 0)
	printf( "false" );
      else
	printf( "%02X", *(unsigned char*)data );
    }
    else if (properties && size == 2 &&
	     (type == (0xFFFF0000 | DEVPROP_TYPE_UINT16) ||
	      type == (0xFFFF0000 | DEVPROP_TYPE_INT16)))
    {
      if ((type & 0xFFFF) == DEVPROP_TYPE_UINT16)
	printf( "0x%X (%u)", *(unsigned short*)data, *(unsigned short*)data );
      else
	printf( "0x%X (%d)", *(unsigned short*)data, *(short*)data );
    }
    // See if 8 bytes is a 21st century FILETIME.
    else if (size == 8 &&
	     (type == REG_QWORD || type == REG_BINARY || type == REG_NONE) &&
	     *(int64_t*)data >= (int64_t)126227808000000000 &&	// 2001-01-01
	     *(int64_t*)data < (int64_t)157784544000000000)	// 2101-01-01
    {
      print_time( *(int64_t*)data, FALSE, FALSE );
      if (type == REG_QWORD)
	printf( " (0x%" PRIX64 "; %" PRId64 ")", *(int64_t*)data, *(int64_t*)data );
      else
      {
	putchar( ' ' );
	putchar( '(' );
	for (i = 0; i < size; i++)
	{
	  if (i)
	    putchar( ',' );
	  printf( "%02X", (unsigned char)data[i] );
	}
	putchar( ')' );
      }
    }
    else if (type == REG_QWORD && size == 8)
    {
      printf( "0x%" PRIX64 " (%" PRId64 ")", *(int64_t*)data, *(int64_t*)data );
    }
    // Strings are stored as Unicode (UTF-16LE).
    else if (type == REG_SZ ||
	     type == REG_MULTI_SZ ||
	     type == REG_EXPAND_SZ ||
	     type == REG_LINK ||
	     bintext == 16)
    {
      unsigned short* us = (unsigned short*)data;
      size /= 2;
      if (!bintext)
	while (size > 0 && us[size-1] == '\0')
	  --size;
      for (i = 0; i < size; ++i)
      {
	if (us[i] >= 32 && us[i] < 127)
	  putchar( us[i] );
	else if (us[i] == '\0' && type == REG_MULTI_SZ && i+1 < size && us[i+1] != '\0')
	  printf( "<>" );
	else if (us[i] == '\0' && !all_string && !bintext)
	{
	  printf( " <...>" );
	  break;
	}
	else
	  printf( "<%0*X>", (us[i] < 0x100) ? 2 : 4, us[i] );
      }
    }
    else if (bintext /*== 8*/)
    {
      for (i = 0; i < size; ++i)
      {
	if (data[i] >= 32 && data[i] < 127)
	  putchar( data[i] );
	else
	  printf( "<%02X>", (unsigned char)data[i] );
      }
    }
    else
    {
      for (i = 0; i < size; ++i)
      {
	if (i)
	  putchar( ',' );
	printf( "%02X", (unsigned char)data[i] );
      }
    }
    putchar( '\n' );

    if (data_block)
    {
      free( data_block );
      data_block = NULL;
    }
  }

children:
  // For simplicity we can imagine keys as directories in filesystem and values
  // as files.	Since we already dumped values for this dir we will now iterate
  // through subdirectories in the same way.
  if (key->subkeys != -1)
  {
    list_block* item = (list_block*)(key->subkeys + root);

    if (item->count)
      empty_key = FALSE;

    if (item->block_type[0] == 'l')
    {
      int ii = (item->block_type[1] == 'i') ? 1 : 2;
      for (i = 0; i < item->count; ++i)
	walk( path, (key_block*)(item->offsets[i*ii] + root) );
    }
    else
    {
      for (i = 0; i < item->count; ++i)
      {
	// In case of too many subkeys this list contains just other lists.
	list_block* subitem = (list_block*)(item->offsets[i] + root);
	int j, jj = (subitem->block_type[1] == 'i') ? 1 : 2;
	for (j = 0; j < subitem->count; ++j)
	  walk( path, (key_block*)(subitem->offsets[j*jj] + root) );
      }
    }
  }

  if (empty_key && !only_values)
  {
    if (time_sec || time_full)
      print_time( key->timestamp, time_full, TRUE );
    if (hex_type)
      printf( "%20c", ' ' );
    printf( "%s\n", full );
  }

  if (leave_key)
    *leave_key = FALSE;
}


int main( int argc, char* argv[] )
{
  char	path[0x4000];
  char* data;
  base_block* regf;
  FILE* f;
  int	size;
  BOOL	show_hive;
  int	rc = 0;
  const char* errmsg;

  if (argc == 1 || strcmp( argv[1], "/?" ) == 0
		|| strcmp( argv[1], "-?" ) == 0
		|| strcmp( argv[1], "--help" ) == 0)
  {
    printf( "Dump a registry hive as text, one line per value.\n"
	    "https://github.com/adoxa/regdump\n"
	    "\n"
	    "regdump [-hkstTv] HIVE...\n"
	    "\n"
	    "-h  use hexadecimal for type & size, placed before key\n"
	    "-k  keys only (implies -t)\n"
	    "-s  include the entire string data (excluding trailing nulls)\n"
	    "-t  include key timestamp (seconds)\n"
	    "-T  include key timestamp (full resolution)\n"
	    "-v  values only\n"
	  );
    return 0;
  }

  while (argc > 1 && *argv[1] == '-')
  {
    while (*++argv[1])
    {
      switch (*argv[1])
      {
	case 'h': hex_type    = TRUE; break;
	case 's': all_string  = TRUE; break;
	case 'v': only_values = TRUE; break;
	case 'k': only_keys   = TRUE; // fall through
	case 't': time_sec    = TRUE; break;
	case 'T': time_full   = TRUE; break;
	default:
	  fprintf( stderr, "%c: unknown option.\n", *argv[1] );
	  return 1;
      }
    }
    ++argv;
    --argc;
  }

  full = path;
  show_hive = (argc > 2);

  for (; argc > 1; ++argv, --argc)
  {
    f = fopen( argv[1], "rb" );
    if (!f)
    {
      perror( argv[1] );
      rc = 1;
      continue;
    }

    if (fread( path, 4, 1, f ) != 1 || memcmp( path, "regf", 4 ) != 0)
    {
      errmsg = "invalid file ('regf' signature not found)";
    error:
      fprintf( stderr, "%s: %s.\n", argv[1], errmsg );
      fclose( f );
      rc = 1;
      continue;
    }

    fseek( f, 0x1000, SEEK_SET );
    if (fread( path, 4, 1, f ) != 1 || memcmp( path, "hbin", 4 ) != 0)
    {
      errmsg = "invalid file ('hbin' signature not found)";
      goto error;
    }

    fseek( f, 0, SEEK_END );
    size = ftell( f );
    data = malloc( size );
    if (!data)
    {
      errmsg = "insufficient memory";
      goto error;
    }

    rewind( f );
    if (fread( data, size, 1, f ) != 1)
    {
      free( data );
      errmsg = "read error";
      goto error;
    }
    fclose( f );

    regf = (base_block*)data;
    big_data = (regf->major_version > 1 || regf->minor_version > 3);

    if (show_hive)
      printf( "%s\n\n", argv[1] );

    // We just skip header and start walking root key tree.
    root = data + 0x1000;
    walk( path, (key_block*)(regf->root_cell_offset + root) );
    free( data );

    if (show_hive && argc > 2)
      putchar( '\n' );
  }

  return rc;
}
