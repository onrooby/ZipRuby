/* rdoc source */
/* $NiH: mkstemp.c,v 1.3 2006/04/23 14:51:45 wiz Exp $ */

/* Adapted from NetBSB libc by Dieter Baron */

/*	NetBSD: gettemp.c,v 1.13 2003/12/05 00:57:36 uebayasi Exp 	*/

/*
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif



int
_zip_mkstemp(char *path)
{
	int fd;   
	char *start, *trv;
	struct stat sbuf;
	pid_t pid;

	/* To guarantee multiple calls generate unique names even if
	   the file is not created. 676 different possibilities with 7
	   or more X's, 26 with 6 or less. */
	static char xtra[2] = "aa";
	int xcnt = 0;

	pid = getpid();

	/* Move to end of path and count trailing X's. */
	for (trv = path; *trv; ++trv)
		if (*trv == 'X')
			xcnt++;
		else
			xcnt = 0;	

	/* Use at least one from xtra.  Use 2 if more than 6 X's. */
	if (*(trv - 1) == 'X')
		*--trv = xtra[0];
	if (xcnt > 6 && *(trv - 1) == 'X')
		*--trv = xtra[1];

	/* Set remaining X's to pid digits with 0's to the left. */
	while (*--trv == 'X') {
		*trv = (pid % 10) + '0';
		pid /= 10;
	}

	/* update xtra for next call. */
	if (xtra[0] != 'z')
		xtra[0]++;
	else {
		xtra[0] = 'a';
		if (xtra[1] != 'z')
			xtra[1]++;
		else
			xtra[1] = 'a';
	}

	/*
	 * check the target directory; if you have six X's and it
	 * doesn't exist this runs for a *very* long time.
	 */
	for (start = trv + 1;; --trv) {
		if (trv <= path)
			break;
		if (*trv == '/') {
			*trv = '\0';
			if (stat(path, &sbuf))
				return (0);
			if (!S_ISDIR(sbuf.st_mode)) {
				errno = ENOTDIR;
				return (0);
			}
			*trv = '/';
			break;
		}
	}

	for (;;) {
		if ((fd=open(path, O_CREAT|O_EXCL|O_RDWR|O_BINARY, 0600)) >= 0)
			return (fd);
		if (errno != EEXIST)
			return (0);

		/* tricky little algorithm for backward compatibility */
		for (trv = start;;) {
			if (!*trv)
				return (0);
			if (*trv == 'z')
				*trv++ = 'a';
			else {
				if (isdigit((unsigned char)*trv))
					*trv = 'a';
				else
					++*trv;
				break;
			}
		}
	}
	/*NOTREACHED*/
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#if RUBY_VERSION_MAJOR == 1 && RUBY_VERSION_MINOR == 8
#include <windows.h>
#endif
#include <io.h>
#include <fcntl.h>
#include <share.h>
#endif

#include "tmpfile.h"
#include "ruby.h"

#ifndef _WIN32
#ifndef HAVE_MKSTEMP
int _zip_mkstemp(char *);
#define mkstemp _zip_mkstemp
#endif
#endif

static int write_from_proc(VALUE proc, int fd);
static VALUE proc_call(VALUE proc);

char *zipruby_tmpnam(void *data, int len) {
  char *filnam;

#ifdef _WIN32
  int fd;
  char tmpdirnam[_MAX_PATH];
  char tmpfilnam[_MAX_PATH];
  int namlen;

  memset(tmpdirnam, 0, _MAX_PATH);

  if (GetTempPathA(_MAX_PATH, tmpdirnam) == 0) {
    return NULL;
  }

  memset(tmpfilnam, 0, _MAX_PATH);

  if (GetTempFileNameA(tmpdirnam, "zrb", 0, tmpfilnam) == 0) {
    return NULL;
  }

  namlen = strlen(tmpfilnam) + 1;

  if ((filnam = calloc(namlen, sizeof(char))) == NULL) {
    return NULL;
  }

  if (strcpy_s(filnam, namlen, tmpfilnam) != 0) {
    free(filnam);
    return NULL;
  }

  if (data) {
    if ((_sopen_s(&fd, filnam, _O_WRONLY | _O_BINARY, _SH_DENYRD, _S_IWRITE)) != 0) {
      free(filnam);
      return NULL;
    }

    if (len < 0) {
      if (write_from_proc((VALUE) data, fd) == -1) {
        free(filnam);
        return NULL;
      }
    } else {
      if (_write(fd, data, len) == -1) {
        free(filnam);
        return NULL;
      }
    }

    if (_close(fd) == -1) {
      free(filnam);
      return NULL;
    }
  }
#else
  int fd;
#ifdef P_tmpdir
  int namlen = 16 + strlen(P_tmpdir);
  char *dirnam = P_tmpdir;
#else
  int namlen = 20;
  char *dirnam = "/tmp";
#endif

  if ((filnam = calloc(namlen, sizeof(char))) == NULL) {
    return NULL;
  }

  strcpy(filnam, dirnam);
  strcat(filnam, "/zipruby.XXXXXX");

  if ((fd = mkstemp(filnam)) == -1) {
    free(filnam);
    return NULL;
  }

  if (data) {
    if (len < 0) {
      if (write_from_proc((VALUE) data, fd) == -1) {
        free(filnam);
        return NULL;
      }
    } else {
      if (write(fd, data, len) == -1) {
        free(filnam);
        return NULL;
      }
    }
  }

  if (close(fd) == -1) {
    free(filnam);
    return NULL;
  }
#endif

  return filnam;
}

void zipruby_rmtmp(const char *tmpfilnam) {
  struct stat st;

  if (!tmpfilnam) {
    return;
  }

  if (stat(tmpfilnam, &st) != 0) {
    return;
  }

#ifdef _WIN32
  _unlink(tmpfilnam);
#else
  unlink(tmpfilnam);
#endif
}

static int write_from_proc(VALUE proc, int fd) {
  while (1) {
    VALUE src = rb_protect(proc_call, proc, NULL);

    if (TYPE(src) != T_STRING) {
      break;
    }

    if (RSTRING_LEN(src) < 1) {
      break;
    }

#ifdef _WIN32
    if (_write(fd, RSTRING_PTR(src), RSTRING_LEN(src)) == -1) {
      return -1;
    }
#else
    if (write(fd, RSTRING_PTR(src), RSTRING_LEN(src)) == -1) {
      return -1;
    }
#endif
  }

  return 0;
}

static VALUE proc_call(VALUE proc) {
  return rb_funcall(proc, rb_intern("call"), 0);
}
/*
  zip_add.c -- add file via callback function
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_add(struct zip *za, const char *name, struct zip_source *source)
{
    if (name == NULL || source == NULL) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }
	
    return _zip_replace(za, -1, name, source);
}
/*
  zip_add_dir.c -- add directory
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>
#include <string.h>

#include "zipint.h"



ZIP_EXTERN int
zip_add_dir(struct zip *za, const char *name)
{
    int len, ret;
    char *s;
    struct zip_source *source;

    if (name == NULL) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    s = NULL;
    len = strlen(name);

    if (name[len-1] != '/') {
	if ((s=(char *)malloc(len+2)) == NULL) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    return -1;
	}
	strcpy(s, name);
	s[len] = '/';
	s[len+1] = '\0';
    }

    if ((source=zip_source_buffer(za, NULL, 0, 0)) == NULL) {
	free(s);
	return -1;
    }
	
    ret = _zip_replace(za, -1, s ? s : name, source);

    free(s);
    if (ret < 0)
	zip_source_free(source);

    return ret;
}
/*
  zip_close.c -- close zip archive and update changes
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "zipint.h"

static int add_data(struct zip *, struct zip_source *, struct zip_dirent *,
		    FILE *);
static int add_data_comp(zip_source_callback, void *, struct zip_stat *,
			 FILE *, struct zip_error *);
// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
// static int add_data_uncomp(struct zip *, zip_source_callback, void *,
// 			   struct zip_stat *, FILE *);
static int add_data_uncomp(struct zip *, zip_source_callback, void *,
			   struct zip_stat *, FILE *, int comp_level);
static void ch_set_error(struct zip_error *, zip_source_callback, void *);
// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
//static int copy_data(FILE *, off_t, FILE *, struct zip_error *);
static int write_cdir(struct zip *, struct zip_cdir *, FILE *);
//static int _zip_cdir_set_comment(struct zip_cdir *, struct zip *);
//static int _zip_changed(struct zip *, int *);
//static char *_zip_create_temp_output(struct zip *, FILE **);
static int _zip_torrentzip_cmp(const void *, const void *);



struct filelist {
    int idx;
    const char *name;
};



ZIP_EXTERN int
zip_close(struct zip *za)
{
    int survivors;
    int i, j, error;
    char *temp;
    FILE *out;
    mode_t mask;
    struct zip_cdir *cd;
    struct zip_dirent de;
    struct filelist *filelist;
    int reopen_on_error;
    int new_torrentzip;

    reopen_on_error = 0;

    if (za == NULL)
	return -1;

    if (!_zip_changed(za, &survivors)) {
	_zip_free(za);
	return 0;
    }

    /* don't create zip files with no entries */
    if (survivors == 0) {
	if (za->zn && za->zp) {
	    if (remove(za->zn) != 0) {
		_zip_error_set(&za->error, ZIP_ER_REMOVE, errno);
		return -1;
	    }
	}
	_zip_free(za);
	return 0;
    }	       

    if ((filelist=(struct filelist *)malloc(sizeof(filelist[0])*survivors))
	== NULL)
	return -1;

    if ((cd=_zip_cdir_new(survivors, &za->error)) == NULL) {
	free(filelist);
	return -1;
    }

    for (i=0; i<survivors; i++)
	_zip_dirent_init(&cd->entry[i]);

    /* archive comment is special for torrentzip */
    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0)) {
	cd->comment = _zip_memdup(TORRENT_SIG "XXXXXXXX",
				  TORRENT_SIG_LEN + TORRENT_CRC_LEN,
				  &za->error);
	if (cd->comment == NULL) {
	    _zip_cdir_free(cd);
	    free(filelist);
	    return -1;
	}
	cd->comment_len = TORRENT_SIG_LEN + TORRENT_CRC_LEN;
    }
    else if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, ZIP_FL_UNCHANGED) == 0) {
	if (_zip_cdir_set_comment(cd, za) == -1) {
	    _zip_cdir_free(cd);
	    free(filelist);
	    return -1;
	}
    }

    if ((temp=_zip_create_temp_output(za, &out)) == NULL) {
	_zip_cdir_free(cd);
	free(filelist);
	return -1;
    }


    /* create list of files with index into original archive  */
    for (i=j=0; i<za->nentry; i++) {
	if (za->entry[i].state == ZIP_ST_DELETED)
	    continue;

	filelist[j].idx = i;
	filelist[j].name = zip_get_name(za, i, 0);
	j++;
    }
    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0))
	qsort(filelist, survivors, sizeof(filelist[0]),
	      _zip_torrentzip_cmp);

    new_torrentzip = (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0) == 1
		      && zip_get_archive_flag(za, ZIP_AFL_TORRENT,
					      ZIP_FL_UNCHANGED) == 0);
    error = 0;
    for (j=0; j<survivors; j++) {
	i = filelist[j].idx;

	/* create new local directory entry */
	if (ZIP_ENTRY_DATA_CHANGED(za->entry+i) || new_torrentzip) {
	    _zip_dirent_init(&de);

	    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0))
		_zip_dirent_torrent_normalize(&de);
		
	    /* use it as central directory entry */
	    memcpy(cd->entry+j, &de, sizeof(cd->entry[j]));

	    /* set/update file name */
	    if (za->entry[i].ch_filename == NULL) {
		if (za->entry[i].state == ZIP_ST_ADDED) {
		    de.filename = strdup("-");
		    de.filename_len = 1;
		    cd->entry[j].filename = "-";
		    cd->entry[j].filename_len = 1;
		}
		else {
		    de.filename = strdup(za->cdir->entry[i].filename);
		    de.filename_len = strlen(de.filename);
		    cd->entry[j].filename = za->cdir->entry[i].filename;
		    cd->entry[j].filename_len = de.filename_len;
		}
	    }
	}
	else {
	    /* copy existing directory entries */
	    if (fseeko(za->zp, za->cdir->entry[i].offset, SEEK_SET) != 0) {
		_zip_error_set(&za->error, ZIP_ER_SEEK, errno);
		error = 1;
		break;
	    }
	    if (_zip_dirent_read(&de, za->zp, NULL, NULL, 1,
				 &za->error) != 0) {
		error = 1;
		break;
	    }
	    memcpy(cd->entry+j, za->cdir->entry+i, sizeof(cd->entry[j]));
	    if (de.bitflags & ZIP_GPBF_DATA_DESCRIPTOR) {
		de.crc = za->cdir->entry[i].crc;
		de.comp_size = za->cdir->entry[i].comp_size;
		de.uncomp_size = za->cdir->entry[i].uncomp_size;
		de.bitflags &= ~ZIP_GPBF_DATA_DESCRIPTOR;
		cd->entry[j].bitflags &= ~ZIP_GPBF_DATA_DESCRIPTOR;
	    }
	}

	if (za->entry[i].ch_filename) {
	    free(de.filename);
	    if ((de.filename=strdup(za->entry[i].ch_filename)) == NULL) {
		error = 1;
		break;
	    }
	    de.filename_len = strlen(de.filename);
	    cd->entry[j].filename = za->entry[i].ch_filename;
	    cd->entry[j].filename_len = de.filename_len;
	}

	if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0) == 0
	    && za->entry[i].ch_comment_len != -1) {
	    /* as the rest of cd entries, its malloc/free is done by za */
	    cd->entry[j].comment = za->entry[i].ch_comment;
	    cd->entry[j].comment_len = za->entry[i].ch_comment_len;
	}

	cd->entry[j].offset = ftello(out);

	if (ZIP_ENTRY_DATA_CHANGED(za->entry+i) || new_torrentzip) {
	    struct zip_source *zs;

	    zs = NULL;
	    if (!ZIP_ENTRY_DATA_CHANGED(za->entry+i)) {
		if ((zs=zip_source_zip(za, za, i, ZIP_FL_RECOMPRESS, 0, -1))
		    == NULL) {
		    error = 1;
		    break;
		}
	    }

	    if (add_data(za, zs ? zs : za->entry[i].source, &de, out) < 0) {
		error = 1;
		break;
	    }
	    cd->entry[j].last_mod = de.last_mod;
	    cd->entry[j].comp_method = de.comp_method;
	    cd->entry[j].comp_size = de.comp_size;
	    cd->entry[j].uncomp_size = de.uncomp_size;
	    cd->entry[j].crc = de.crc;
	}
	else {
	    if (_zip_dirent_write(&de, out, 1, &za->error) < 0) {
		error = 1;
		break;
	    }
	    /* we just read the local dirent, file is at correct position */
	    if (copy_data(za->zp, cd->entry[j].comp_size, out,
			  &za->error) < 0) {
		error = 1;
		break;
	    }
	}

	_zip_dirent_finalize(&de);
    }

    free(filelist);

    if (!error) {
	if (write_cdir(za, cd, out) < 0)
	    error = 1;
    }
   
    /* pointers in cd entries are owned by za */
    cd->nentry = 0;
    _zip_cdir_free(cd);

    if (error) {
	_zip_dirent_finalize(&de);
	fclose(out);
	remove(temp);
	free(temp);
	return -1;
    }

    if (fclose(out) != 0) {
	_zip_error_set(&za->error, ZIP_ER_CLOSE, errno);
	remove(temp);
	free(temp);
	return -1;
    }
    
    if (za->zp) {
	fclose(za->zp);
	za->zp = NULL;
	reopen_on_error = 1;
    }
    if (_zip_rename(temp, za->zn) != 0) {
	_zip_error_set(&za->error, ZIP_ER_RENAME, errno);
	remove(temp);
	free(temp);
	if (reopen_on_error) {
	    /* ignore errors, since we're already in an error case */
	    za->zp = fopen(za->zn, "rb");
	}
	return -1;
    }
    mask = umask(0);
    umask(mask);
    chmod(za->zn, 0666&~mask);

    _zip_free(za);
    free(temp);
    
    return 0;
}



static int
add_data(struct zip *za, struct zip_source *zs, struct zip_dirent *de, FILE *ft)
{
    off_t offstart, offend;
    zip_source_callback cb;
    void *ud;
    struct zip_stat st;
    
    cb = zs->f;
    ud = zs->ud;

    if (cb(ud, &st, sizeof(st), ZIP_SOURCE_STAT) < (ssize_t)sizeof(st)) {
	ch_set_error(&za->error, cb, ud);
	return -1;
    }

    if (cb(ud, NULL, 0, ZIP_SOURCE_OPEN) < 0) {
	ch_set_error(&za->error, cb, ud);
	return -1;
    }

    offstart = ftello(ft);

    if (_zip_dirent_write(de, ft, 1, &za->error) < 0)
	return -1;

    if (st.comp_method != ZIP_CM_STORE) {
	if (add_data_comp(cb, ud, &st, ft, &za->error) < 0)
	    return -1;
    }
    else {
	if (add_data_uncomp(za, cb, ud, &st, ft, za->comp_level) < 0)
	    return -1;
    }

    if (cb(ud, NULL, 0, ZIP_SOURCE_CLOSE) < 0) {
	ch_set_error(&za->error, cb, ud);
	return -1;
    }

    offend = ftello(ft);

    if (fseeko(ft, offstart, SEEK_SET) < 0) {
	_zip_error_set(&za->error, ZIP_ER_SEEK, errno);
	return -1;
    }

    
    de->last_mod = st.mtime;
    de->comp_method = st.comp_method;
    de->crc = st.crc;
    de->uncomp_size = st.size;
    de->comp_size = st.comp_size;

    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0))
	_zip_dirent_torrent_normalize(de);

    if (_zip_dirent_write(de, ft, 1, &za->error) < 0)
	return -1;
    
    if (fseeko(ft, offend, SEEK_SET) < 0) {
	_zip_error_set(&za->error, ZIP_ER_SEEK, errno);
	return -1;
    }

    return 0;
}



static int
add_data_comp(zip_source_callback cb, void *ud, struct zip_stat *st,FILE *ft,
	      struct zip_error *error)
{
    char buf[BUFSIZE];
    ssize_t n;

    st->comp_size = 0;
    while ((n=cb(ud, buf, sizeof(buf), ZIP_SOURCE_READ)) > 0) {
	if (fwrite(buf, 1, n, ft) != (size_t)n) {
	    _zip_error_set(error, ZIP_ER_WRITE, errno);
	    return -1;
	}
	
	st->comp_size += n;
    }
    if (n < 0) {
	ch_set_error(error, cb, ud);
	return -1;
    }	

    return 0;
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
static int
add_data_uncomp(struct zip *za, zip_source_callback cb, void *ud,
		struct zip_stat *st, FILE *ft, int comp_level)
{
    char b1[BUFSIZE], b2[BUFSIZE];
    int end, flush, ret;
    ssize_t n;
    size_t n2;
    z_stream zstr;
    int mem_level;

    st->comp_method = ZIP_CM_DEFLATE;
    st->comp_size = st->size = 0;
    st->crc = crc32(0, NULL, 0);

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = NULL;
    zstr.avail_in = 0;
    zstr.avail_out = 0;

    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0))
	mem_level = TORRENT_MEM_LEVEL;
    else
	mem_level = MAX_MEM_LEVEL;

    /* -MAX_WBITS: undocumented feature of zlib to _not_ write a zlib header */
    // modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
    deflateInit2(&zstr, comp_level, Z_DEFLATED, -MAX_WBITS, mem_level,
		 Z_DEFAULT_STRATEGY);

    zstr.next_out = (Bytef *)b2;
    zstr.avail_out = sizeof(b2);
    zstr.next_in = NULL;
    zstr.avail_in = 0;

    flush = 0;
    end = 0;
    while (!end) {
	if (zstr.avail_in == 0 && !flush) {
	    if ((n=cb(ud, b1, sizeof(b1), ZIP_SOURCE_READ)) < 0) {
		ch_set_error(&za->error, cb, ud);
		deflateEnd(&zstr);
		return -1;
	    }
	    if (n > 0) {
		zstr.avail_in = n;
		zstr.next_in = (Bytef *)b1;
		st->size += n;
		st->crc = crc32(st->crc, (Bytef *)b1, n);
	    }
	    else
		flush = Z_FINISH;
	}

	ret = deflate(&zstr, flush);
	if (ret != Z_OK && ret != Z_STREAM_END) {
	    _zip_error_set(&za->error, ZIP_ER_ZLIB, ret);
	    return -1;
	}
	
	if (zstr.avail_out != sizeof(b2)) {
	    n2 = sizeof(b2) - zstr.avail_out;
	    
	    if (fwrite(b2, 1, n2, ft) != n2) {
		_zip_error_set(&za->error, ZIP_ER_WRITE, errno);
		return -1;
	    }
	
	    zstr.next_out = (Bytef *)b2;
	    zstr.avail_out = sizeof(b2);
	    st->comp_size += n2;
	}

	if (ret == Z_STREAM_END) {
	    deflateEnd(&zstr);
	    end = 1;
	}
    }

    return 0;
}



static void
ch_set_error(struct zip_error *error, zip_source_callback cb, void *ud)
{
    int e[2];

    if ((cb(ud, e, sizeof(e), ZIP_SOURCE_ERROR)) < (ssize_t)sizeof(e)) {
	error->zip_err = ZIP_ER_INTERNAL;
	error->sys_err = 0;
    }
    else {
	error->zip_err = e[0];
	error->sys_err = e[1];
    }
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
/*static*/ int
copy_data(FILE *fs, off_t len, FILE *ft, struct zip_error *error)
{
    char buf[BUFSIZE];
    int n, nn;

    if (len == 0)
	return 0;

    while (len > 0) {
	nn = len > sizeof(buf) ? sizeof(buf) : len;
	if ((n=fread(buf, 1, nn, fs)) < 0) {
	    _zip_error_set(error, ZIP_ER_READ, errno);
	    return -1;
	}
	else if (n == 0) {
	    _zip_error_set(error, ZIP_ER_EOF, 0);
	    return -1;
	}

	if (fwrite(buf, 1, n, ft) != (size_t)n) {
	    _zip_error_set(error, ZIP_ER_WRITE, errno);
	    return -1;
	}
	
	len -= n;
    }

    return 0;
}



static int
write_cdir(struct zip *za, struct zip_cdir *cd, FILE *out)
{
    off_t offset;
    uLong crc;
    char buf[TORRENT_CRC_LEN+1];
    
    if (_zip_cdir_write(cd, out, &za->error) < 0)
	return -1;
    
    if (zip_get_archive_flag(za, ZIP_AFL_TORRENT, 0) == 0)
	return 0;


    /* fix up torrentzip comment */

    offset = ftello(out);

    if (_zip_filerange_crc(out, cd->offset, cd->size, &crc, &za->error) < 0)
	return -1;

    snprintf(buf, sizeof(buf), "%08lX", (long)crc);

    if (fseeko(out, offset-TORRENT_CRC_LEN, SEEK_SET) < 0) {
	_zip_error_set(&za->error, ZIP_ER_SEEK, errno);
	return -1;
    }

    if (fwrite(buf, TORRENT_CRC_LEN, 1, out) != 1) {
	_zip_error_set(&za->error, ZIP_ER_WRITE, errno);
	return -1;
    }

    return 0;
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
/*static*/ int
_zip_cdir_set_comment(struct zip_cdir *dest, struct zip *src)
{
    if (src->ch_comment_len != -1) {
	dest->comment = _zip_memdup(src->ch_comment,
				    src->ch_comment_len, &src->error);
	if (dest->comment == NULL)
	    return -1;
	dest->comment_len = src->ch_comment_len;
    } else {
	if (src->cdir && src->cdir->comment) {
	    dest->comment = _zip_memdup(src->cdir->comment,
					src->cdir->comment_len, &src->error);
	    if (dest->comment == NULL)
		return -1;
	    dest->comment_len = src->cdir->comment_len;
	}
    }

    return 0;
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
/*static*/ int
_zip_changed(struct zip *za, int *survivorsp)
{
    int changed, i, survivors;

    changed = survivors = 0;

    if (za->ch_comment_len != -1
	|| za->ch_flags != za->flags)
	changed = 1;

    for (i=0; i<za->nentry; i++) {
	if ((za->entry[i].state != ZIP_ST_UNCHANGED)
	    || (za->entry[i].ch_comment_len != -1))
	    changed = 1;
	if (za->entry[i].state != ZIP_ST_DELETED)
	    survivors++;
    }

    *survivorsp = survivors;

    return changed;
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
/*static*/ char *
_zip_create_temp_output(struct zip *za, FILE **outp)
{
    char *temp;
    int tfd;
    FILE *tfp;
    
    if ((temp=(char *)malloc(strlen(za->zn)+8)) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    sprintf(temp, "%s.XXXXXX", za->zn);

    if ((tfd=mkstemp(temp)) == -1) {
	_zip_error_set(&za->error, ZIP_ER_TMPOPEN, errno);
	free(temp);
	return NULL;
    }
    
    if ((tfp=fdopen(tfd, "r+b")) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_TMPOPEN, errno);
	close(tfd);
	remove(temp);
	free(temp);
	return NULL;
    }

    *outp = tfp;
    return temp;
}



static int
_zip_torrentzip_cmp(const void *a, const void *b)
{
    return strcasecmp(((const struct filelist *)a)->name,
		      ((const struct filelist *)b)->name);
}
/*
 zip_crypt.c -- zip encryption support
 Copyright (c) 2008 SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
 based on zip_close.c
*/
/*
  $NiH: zip_close.c,v 1.65 2007/02/28 10:44:15 wiz Exp $

  zip_close.c -- close zip archive and update changes
  Copyright (C) 1999, 2004, 2005, 2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <nih@giga.or.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define close(f) _close(f)
#define rename(s, d) (MoveFileExA((s), (d), MOVEFILE_REPLACE_EXISTING) ? 0 : -1)
#endif

#include "zip.h"
#include "zipint.h"

#define ZIPENC_HEAD_LEN 12
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static zipenc_crc32(uLong crc, char c) {
  return crc32(crc ^ 0xffffffffL, &c, 1) ^ 0xffffffffL;
}

static void update_keys(uLong *keys, char c) {
  keys[0] = zipenc_crc32(keys[0], c);
  keys[1] = keys[1] + (keys[0] & 0xff);
  keys[1] = keys[1] * 134775813L + 1;
  c = (char) (keys[1] >> 24);
  keys[2] = zipenc_crc32(keys[2], c);
}

static unsigned char decrypt_byte(uLong *keys) {
  unsigned short temp;

  temp = (unsigned short) (keys[2] | 2);
  return (temp * (temp ^ 1)) >> 8;
}

static void init_keys(uLong *keys, const char *password, size_t len) {
  int i;

  keys[0] = 305419896L;
  keys[1] = 591751049L;
  keys[2] = 878082192L;

  for (i = 0; i < len; i++) {
    update_keys(keys, password[i]);
  }
}

static int decrypt_header(unsigned long *keys, char *buffer, struct zip_dirent *de) {
  int i;
  char c;

  for (i = 0; i < ZIPENC_HEAD_LEN; i++) {
    c = buffer[i] ^ decrypt_byte(keys);
    update_keys(keys, c);
    buffer[i] = c;
  }

  if (de->bitflags & ZIP_GPBF_DATA_DESCRIPTOR) {
    unsigned short dostime, dosdate;
    _zip_u2d_time(de->last_mod, &dostime, &dosdate);
    return ((c & 0xff) == (dostime >> 8)) ? 0 : -1;
  } else {
    return ((c & 0xff) == (de->crc >> 24)) ? 0 : -1;
  }
}

static void decrypt_data(uLong *keys, char *buffer, size_t n) {
  int i;

  for (i = 0; i < n; i++) {
    char temp = buffer[i] ^ decrypt_byte(keys);
    update_keys(keys, temp);
    buffer[i] = temp;
  }
}

static int copy_decrypt(FILE *src, off_t len, const char *pwd, int pwdlen, struct zip_dirent *de, FILE *dest, struct zip_error *error, int *wrongpwd) {
  char buf[BUFSIZE];
  uLong keys[3];
  int n;

  *wrongpwd = 0;

  if (len == 0) {
    return 0;
  }

  init_keys(keys, pwd, pwdlen);

  if (fread(buf, 1, ZIPENC_HEAD_LEN, src) < 0) {
    _zip_error_set(error, ZIP_ER_READ, errno);
  }

  if (decrypt_header(keys, buf, de) == -1) {
    // XXX: _zip_error_set
    *wrongpwd = 1;
    return -1;
  }

  while (len > 0) {
    if ((n = fread(buf, 1, MIN(len,  sizeof(buf)), src)) < 0) {
      _zip_error_set(error, ZIP_ER_READ, errno);
      return -1;
    } else if (n == 0) {
      _zip_error_set(error, ZIP_ER_EOF, 0);
      return -1;
    }

    decrypt_data(keys, buf, n);

    if (fwrite(buf, 1, n, dest) != ((size_t) n)) {
      _zip_error_set(error, ZIP_ER_WRITE, errno);
      return -1;
    }

    len -= n;
  }

  return 0;
}

static void generate_random_header(unsigned long *keys, char *buffer) {
  static int initialized = 0;
  int i;

  if (!initialized) {
    srand((unsigned) time(NULL));
    initialized = 1;
  }

  for (i = 0; i < ZIPENC_HEAD_LEN - 2; i++) {
    char temp = decrypt_byte(keys);
    char c = rand() % 0xff;
    update_keys(keys, c);
    buffer[i] = temp ^ c;
  }
}

static void encrypt_header(unsigned long *keys, char *buffer, struct zip_dirent *de) {
  int i;
  char c, temp;

  for (i = 0; i < ZIPENC_HEAD_LEN - 2; i++) {
    temp = decrypt_byte(keys);
    c = buffer[i];
    update_keys(keys, c);
    buffer[i] = temp ^ c;
  }

  temp = decrypt_byte(keys);
  c = (de->crc >> 16) & 0xff;
  update_keys(keys, c);
  buffer[ZIPENC_HEAD_LEN - 2] = temp ^ c;

  temp = decrypt_byte(keys);
  c = (de->crc >> 24) & 0xff;
  update_keys(keys, c);
  buffer[ZIPENC_HEAD_LEN - 1] = temp ^ c;
}

static void encrypt_data(uLong *keys, char *buffer, size_t n) {
  int i;

  for (i = 0; i < n; i++) {
    char temp = decrypt_byte(keys);
    char c = buffer[i];
    update_keys(keys, c);
    buffer[i] = temp ^ c;
  }
}

static int copy_encrypt(FILE *src, off_t len, const char *pwd, int pwdlen, struct zip_dirent *de, FILE *dest, struct zip_error *error) {
  char header[ZIPENC_HEAD_LEN];
  char buf[BUFSIZE];
  uLong keys[3];
  int n;

  if (len == 0) {
    return 0;
  }

  init_keys(keys, pwd, pwdlen);
  generate_random_header(keys, header);
  init_keys(keys, pwd, pwdlen);
  encrypt_header(keys, header, de);

  if (fwrite(header, 1, ZIPENC_HEAD_LEN, dest) != ((size_t) ZIPENC_HEAD_LEN)) {
    _zip_error_set(error, ZIP_ER_WRITE, errno);
  }

  while (len > 0) {
    if ((n = fread(buf, 1, MIN(len,  sizeof(buf)), src)) < 0) {
      _zip_error_set(error, ZIP_ER_READ, errno);
      return -1;
    } else if (n == 0) {
      _zip_error_set(error, ZIP_ER_EOF, 0);
      return -1;
    }

    encrypt_data(keys, buf, n);

    if (fwrite(buf, 1, n, dest) != ((size_t) n)) {
      _zip_error_set(error, ZIP_ER_WRITE, errno);
      return -1;
    }

    len -= n;
  }

  return 0;
}

static int _zip_crypt(struct zip *za, const char *pwd, int pwdlen, int decrypt, int *wrongpwd) {
  int translated = 0;
  int i, error = 0;
  char *temp;
  FILE *out;
#ifndef _WIN32
  mode_t mask;
#endif
  struct zip_cdir *cd;
  struct zip_dirent de;
  int reopen_on_error = 0;

  if (za == NULL) {
    return -1;
  }

  if (za->nentry < 1) {
    _zip_free(za);
    return 0;
  }

  if ((cd = _zip_cdir_new(za->nentry, &za->error)) == NULL) {
    return -1;
  }

  for (i = 0; i < za->nentry; i++) {
    _zip_dirent_init(&cd->entry[i]);
  }

  if (_zip_cdir_set_comment(cd, za) == -1) {
    _zip_cdir_free(cd);
    return -1;
  }

  if ((temp = _zip_create_temp_output(za, &out)) == NULL) {
    _zip_cdir_free(cd);
    return -1;
  }

  for (i = 0; i < za->nentry; i++) {
    struct zip_dirent fde;
    int encrypted;
    unsigned int comp_size;

    if (fseeko(za->zp, za->cdir->entry[i].offset, SEEK_SET) != 0) {
      _zip_error_set(&za->error, ZIP_ER_SEEK, errno);
      error = 1;
      break;
    }

    if (_zip_dirent_read(&de, za->zp, NULL, 0, 1, &za->error) != 0) {
      error = 1;
      break;
    }

    memcpy(&fde, &de, sizeof(fde));
    encrypted = de.bitflags & ZIP_GPBF_ENCRYPTED;

    if (de.bitflags & ZIP_GPBF_DATA_DESCRIPTOR) {
      de.crc = za->cdir->entry[i].crc;
      de.comp_size = za->cdir->entry[i].comp_size;
      de.uncomp_size = za->cdir->entry[i].uncomp_size;
      de.bitflags &= ~ZIP_GPBF_DATA_DESCRIPTOR;
    }

    memcpy(cd->entry + i, za->cdir->entry + i, sizeof(cd->entry[i]));
    comp_size = cd->entry[i].comp_size;

    if (cd->entry[i].bitflags & ZIP_GPBF_DATA_DESCRIPTOR) {
      cd->entry[i].bitflags &= ~ZIP_GPBF_DATA_DESCRIPTOR;
    }

    cd->entry[i].offset = ftello(out);

    if (decrypt && encrypted) {
      de.comp_size -= ZIPENC_HEAD_LEN;
      de.bitflags &= ~ZIP_GPBF_ENCRYPTED;
      cd->entry[i].comp_size -= ZIPENC_HEAD_LEN;
      cd->entry[i].bitflags &= ~ZIP_GPBF_ENCRYPTED;
      translated = 1;
    } else if (!decrypt && !encrypted) {
      de.comp_size += ZIPENC_HEAD_LEN;
      de.bitflags |= ZIP_GPBF_ENCRYPTED;
      cd->entry[i].comp_size += ZIPENC_HEAD_LEN;
      cd->entry[i].bitflags |= ZIP_GPBF_ENCRYPTED;
      translated = 1;
    }

    if (_zip_dirent_write(&de, out, 1, &za->error) < 0) {
      error = 1;
      break;
    }

    if (decrypt && encrypted) {
      error = (copy_decrypt(za->zp, comp_size, pwd, pwdlen, &fde, out, &za->error, wrongpwd) < 0);
    } else if (!decrypt && !encrypted) {
      error = (copy_encrypt(za->zp, comp_size, pwd, pwdlen, &fde, out, &za->error) < 0);
    } else {
      error = (copy_data(za->zp, comp_size, out, &za->error) < 0);
    }

    if (error) {
      break;
    }

    _zip_dirent_finalize(&de);
  }

  if (!error && _zip_cdir_write(cd, out, &za->error) < 0) {
    error = 1;
  }

  cd->nentry = 0;
  _zip_cdir_free(cd);

  if (error) {
    _zip_dirent_finalize(&de);
    fclose(out);
    remove(temp);
    free(temp);
    return -1;
  }

  if (fclose(out) != 0) {
    _zip_error_set(&za->error, ZIP_ER_CLOSE, errno);
    remove(temp);
    free(temp);
    return -1;
  }

  if (za->zp) {
    fclose(za->zp);
    za->zp = NULL;
    reopen_on_error = 1;
  }

  if (rename(temp, za->zn) != 0) {
    _zip_error_set(&za->error, ZIP_ER_RENAME, errno);
    remove(temp);
    free(temp);

    if (reopen_on_error) {
      za->zp = fopen(za->zn, "rb");
    }

    return -1;
  }

#ifndef _WIN32
  mask = umask(0);
  umask(mask);
  chmod(za->zn, 0666&~mask);
#endif

  free(temp);
  return translated;
}

int zip_decrypt(const char *path, const char *pwd, int pwdlen, int *errorp, int *wrongpwd) {
  struct zip *za;
  int res;

  if (pwd == NULL || pwdlen < 1) {
    return -1;
  }

  if ((za = zip_open(path, 0, errorp)) == NULL) {
    return -1;
  }

  res = _zip_crypt(za, pwd, pwdlen, 1, wrongpwd);
  _zip_free(za);

  return res;
}

int zip_encrypt(const char *path, const char *pwd, int pwdlen, int *errorp) {
  struct zip *za;
  int res;

  if (pwd == NULL || pwdlen < 1) {
    return -1;
  }

  if ((za = zip_open(path, 0, errorp)) == NULL) {
    return -1;
  }

  res = _zip_crypt(za, pwd, pwdlen, 0, NULL);
  _zip_free(za);

  return res;
}
/*
  zip_delete.c -- delete file from zip archive
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_delete(struct zip *za, int idx)
{
    if (idx < 0 || idx >= za->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    /* allow duplicate file names, because the file will
     * be removed directly afterwards */
    if (_zip_unchange(za, idx, 1) != 0)
	return -1;

    za->entry[idx].state = ZIP_ST_DELETED;

    return 0;
}


/*
  zip_dirent.c -- read directory entry (local or central), clean dirent
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "zipint.h"

static time_t _zip_d2u_time(int, int);
static char *_zip_readfpstr(FILE *, unsigned int, int, struct zip_error *);
static char *_zip_readstr(unsigned char **, int, int, struct zip_error *);
// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
//static void _zip_u2d_time(time_t, unsigned short *, unsigned short *);
static void _zip_write2(unsigned short, FILE *);
static void _zip_write4(unsigned int, FILE *);



void
_zip_cdir_free(struct zip_cdir *cd)
{
    int i;

    if (!cd)
	return;

    for (i=0; i<cd->nentry; i++)
	_zip_dirent_finalize(cd->entry+i);
    free(cd->comment);
    free(cd->entry);
    free(cd);
}



int
_zip_cdir_grow(struct zip_cdir *cd, int nentry, struct zip_error *error)
{
    struct zip_dirent *entry;

    if (nentry < cd->nentry) {
	_zip_error_set(error, ZIP_ER_INTERNAL, 0);
	return -1;
    }

    if ((entry=((struct zip_dirent *)
		realloc(cd->entry, sizeof(*(cd->entry))*nentry))) == NULL) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return -1;
    }

    cd->nentry = nentry;
    cd->entry = entry;

    return 0;
}



struct zip_cdir *
_zip_cdir_new(int nentry, struct zip_error *error)
{
    struct zip_cdir *cd;
    
    if ((cd=(struct zip_cdir *)malloc(sizeof(*cd))) == NULL) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    if ((cd->entry=(struct zip_dirent *)malloc(sizeof(*(cd->entry))*nentry))
	== NULL) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	free(cd);
	return NULL;
    }

    /* entries must be initialized by caller */

    cd->nentry = nentry;
    cd->size = cd->offset = 0;
    cd->comment = NULL;
    cd->comment_len = 0;

    return cd;
}



int
_zip_cdir_write(struct zip_cdir *cd, FILE *fp, struct zip_error *error)
{
    int i;

    cd->offset = ftello(fp);

    for (i=0; i<cd->nentry; i++) {
	if (_zip_dirent_write(cd->entry+i, fp, 0, error) != 0)
	    return -1;
    }

    cd->size = ftello(fp) - cd->offset;
    
    /* clearerr(fp); */
    fwrite(EOCD_MAGIC, 1, 4, fp);
    _zip_write4(0, fp);
    _zip_write2((unsigned short)cd->nentry, fp);
    _zip_write2((unsigned short)cd->nentry, fp);
    _zip_write4(cd->size, fp);
    _zip_write4(cd->offset, fp);
    _zip_write2(cd->comment_len, fp);
    fwrite(cd->comment, 1, cd->comment_len, fp);

    if (ferror(fp)) {
	_zip_error_set(error, ZIP_ER_WRITE, errno);
	return -1;
    }

    return 0;
}



void
_zip_dirent_finalize(struct zip_dirent *zde)
{
    free(zde->filename);
    zde->filename = NULL;
    free(zde->extrafield);
    zde->extrafield = NULL;
    free(zde->comment);
    zde->comment = NULL;
}



void
_zip_dirent_init(struct zip_dirent *de)
{
    de->version_madeby = 0;
    de->version_needed = 20; /* 2.0 */
    de->bitflags = 0;
    de->comp_method = 0;
    de->last_mod = 0;
    de->crc = 0;
    de->comp_size = 0;
    de->uncomp_size = 0;
    de->filename = NULL;
    de->filename_len = 0;
    de->extrafield = NULL;
    de->extrafield_len = 0;
    de->comment = NULL;
    de->comment_len = 0;
    de->disk_number = 0;
    de->int_attrib = 0;
    de->ext_attrib = 0;
    de->offset = 0;
}



/* _zip_dirent_read(zde, fp, bufp, left, localp, error):
   Fills the zip directory entry zde.

   If bufp is non-NULL, data is taken from there and bufp is advanced
   by the amount of data used; otherwise data is read from fp as needed.
   
   if leftp is non-NULL, no more bytes than specified by it are used,
   and *leftp is reduced by the number of bytes used.

   If local != 0, it reads a local header instead of a central
   directory entry.

   Returns 0 if successful. On error, error is filled in and -1 is
   returned.

   XXX: leftp and file position undefined on error.
*/

int
_zip_dirent_read(struct zip_dirent *zde, FILE *fp,
		 unsigned char **bufp, unsigned int *leftp, int local,
		 struct zip_error *error)
{
    unsigned char buf[CDENTRYSIZE];
    unsigned char *cur;
    unsigned short dostime, dosdate;
    unsigned int size;

    if (local)
	size = LENTRYSIZE;
    else
	size = CDENTRYSIZE;

    if (leftp && (*leftp < size)) {
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	return -1;
    }

    if (bufp) {
	/* use data from buffer */
	cur = *bufp;
    }
    else {
	/* read entry from disk */
	if ((fread(buf, 1, size, fp)<size)) {
	    _zip_error_set(error, ZIP_ER_READ, errno);
	    return -1;
	}
	cur = buf;
    }

    if (memcmp(cur, (local ? LOCAL_MAGIC : CENTRAL_MAGIC), 4) != 0) {
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	return -1;
    }
    cur += 4;

    
    /* convert buffercontents to zip_dirent */
    
    if (!local)
	zde->version_madeby = _zip_read2(&cur);
    else
	zde->version_madeby = 0;
    zde->version_needed = _zip_read2(&cur);
    zde->bitflags = _zip_read2(&cur);
    zde->comp_method = _zip_read2(&cur);
    
    /* convert to time_t */
    dostime = _zip_read2(&cur);
    dosdate = _zip_read2(&cur);
    zde->last_mod = _zip_d2u_time(dostime, dosdate);
    
    zde->crc = _zip_read4(&cur);
    zde->comp_size = _zip_read4(&cur);
    zde->uncomp_size = _zip_read4(&cur);
    
    zde->filename_len = _zip_read2(&cur);
    zde->extrafield_len = _zip_read2(&cur);
    
    if (local) {
	zde->comment_len = 0;
	zde->disk_number = 0;
	zde->int_attrib = 0;
	zde->ext_attrib = 0;
	zde->offset = 0;
    } else {
	zde->comment_len = _zip_read2(&cur);
	zde->disk_number = _zip_read2(&cur);
	zde->int_attrib = _zip_read2(&cur);
	zde->ext_attrib = _zip_read4(&cur);
	zde->offset = _zip_read4(&cur);
    }

    zde->filename = NULL;
    zde->extrafield = NULL;
    zde->comment = NULL;

    size += zde->filename_len+zde->extrafield_len+zde->comment_len;

    if (leftp && (*leftp < size)) {
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	return -1;
    }

    if (bufp) {
	if (zde->filename_len) {
	    zde->filename = _zip_readstr(&cur, zde->filename_len, 1, error);
	    if (!zde->filename)
		    return -1;
	}

	if (zde->extrafield_len) {
	    zde->extrafield = _zip_readstr(&cur, zde->extrafield_len, 0,
					   error);
	    if (!zde->extrafield)
		return -1;
	}

	if (zde->comment_len) {
	    zde->comment = _zip_readstr(&cur, zde->comment_len, 0, error);
	    if (!zde->comment)
		return -1;
	}
    }
    else {
	if (zde->filename_len) {
	    zde->filename = _zip_readfpstr(fp, zde->filename_len, 1, error);
	    if (!zde->filename)
		    return -1;
	}

	if (zde->extrafield_len) {
	    zde->extrafield = _zip_readfpstr(fp, zde->extrafield_len, 0,
					     error);
	    if (!zde->extrafield)
		return -1;
	}

	if (zde->comment_len) {
	    zde->comment = _zip_readfpstr(fp, zde->comment_len, 0, error);
	    if (!zde->comment)
		return -1;
	}
    }

    if (bufp)
      *bufp = cur;
    if (leftp)
	*leftp -= size;

    return 0;
}



/* _zip_dirent_torrent_normalize(de);
   Set values suitable for torrentzip.
*/

void
_zip_dirent_torrent_normalize(struct zip_dirent *de)
{
    static struct tm torrenttime;
    static time_t last_mod = 0;

    if (last_mod == 0) {
#ifdef HAVE_STRUCT_TM_TM_ZONE
	time_t now;
	struct tm *l;
#endif

	torrenttime.tm_sec = 0;
	torrenttime.tm_min = 32;
	torrenttime.tm_hour = 23;
	torrenttime.tm_mday = 24;
	torrenttime.tm_mon = 11;
	torrenttime.tm_year = 96;
	torrenttime.tm_wday = 0;
	torrenttime.tm_yday = 0;
	torrenttime.tm_isdst = 0;

#ifdef HAVE_STRUCT_TM_TM_ZONE
	time(&now);
	l = localtime(&now);
	torrenttime.tm_gmtoff = l->tm_gmtoff;
	torrenttime.tm_zone = l->tm_zone;
#endif

	last_mod = mktime(&torrenttime);
    }
    
    de->version_madeby = 0;
    de->version_needed = 20; /* 2.0 */
    de->bitflags = 2; /* maximum compression */
    de->comp_method = ZIP_CM_DEFLATE;
    de->last_mod = last_mod;

    de->disk_number = 0;
    de->int_attrib = 0;
    de->ext_attrib = 0;
    de->offset = 0;

    free(de->extrafield);
    de->extrafield = NULL;
    de->extrafield_len = 0;
    free(de->comment);
    de->comment = NULL;
    de->comment_len = 0;
}



/* _zip_dirent_write(zde, fp, localp, error):
   Writes zip directory entry zde to file fp.

   If localp != 0, it writes a local header instead of a central
   directory entry.

   Returns 0 if successful. On error, error is filled in and -1 is
   returned.
*/

int
_zip_dirent_write(struct zip_dirent *zde, FILE *fp, int localp,
		  struct zip_error *error)
{
    unsigned short dostime, dosdate;

    fwrite(localp ? LOCAL_MAGIC : CENTRAL_MAGIC, 1, 4, fp);

    if (!localp)
	_zip_write2(zde->version_madeby, fp);
    _zip_write2(zde->version_needed, fp);
    _zip_write2(zde->bitflags, fp);
    _zip_write2(zde->comp_method, fp);

    _zip_u2d_time(zde->last_mod, &dostime, &dosdate);
    _zip_write2(dostime, fp);
    _zip_write2(dosdate, fp);
    
    _zip_write4(zde->crc, fp);
    _zip_write4(zde->comp_size, fp);
    _zip_write4(zde->uncomp_size, fp);
    
    _zip_write2(zde->filename_len, fp);
    _zip_write2(zde->extrafield_len, fp);
    
    if (!localp) {
	_zip_write2(zde->comment_len, fp);
	_zip_write2(zde->disk_number, fp);
	_zip_write2(zde->int_attrib, fp);
	_zip_write4(zde->ext_attrib, fp);
	_zip_write4(zde->offset, fp);
    }

    if (zde->filename_len)
	fwrite(zde->filename, 1, zde->filename_len, fp);

    if (zde->extrafield_len)
	fwrite(zde->extrafield, 1, zde->extrafield_len, fp);

    if (!localp) {
	if (zde->comment_len)
	    fwrite(zde->comment, 1, zde->comment_len, fp);
    }

    if (ferror(fp)) {
	_zip_error_set(error, ZIP_ER_WRITE, errno);
	return -1;
    }

    return 0;
}



static time_t
_zip_d2u_time(int dtime, int ddate)
{
    struct tm tm;

    memset(&tm, sizeof(tm), 0);
    
    /* let mktime decide if DST is in effect */
    tm.tm_isdst = -1;
    
    tm.tm_year = ((ddate>>9)&127) + 1980 - 1900;
    tm.tm_mon = ((ddate>>5)&15) - 1;
    tm.tm_mday = ddate&31;

    tm.tm_hour = (dtime>>11)&31;
    tm.tm_min = (dtime>>5)&63;
    tm.tm_sec = (dtime<<1)&62;

    return mktime(&tm);
}



unsigned short
_zip_read2(unsigned char **a)
{
    unsigned short ret;

    ret = (*a)[0]+((*a)[1]<<8);
    *a += 2;

    return ret;
}



unsigned int
_zip_read4(unsigned char **a)
{
    unsigned int ret;

    ret = ((((((*a)[3]<<8)+(*a)[2])<<8)+(*a)[1])<<8)+(*a)[0];
    *a += 4;

    return ret;
}



static char *
_zip_readfpstr(FILE *fp, unsigned int len, int nulp, struct zip_error *error)
{
    char *r, *o;

    r = (char *)malloc(nulp ? len+1 : len);
    if (!r) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    if (fread(r, 1, len, fp)<len) {
	free(r);
	_zip_error_set(error, ZIP_ER_READ, errno);
	return NULL;
    }

    if (nulp) {
	/* replace any in-string NUL characters with spaces */
	r[len] = 0;
	for (o=r; o<r+len; o++)
	    if (*o == '\0')
		*o = ' ';
    }
    
    return r;
}



static char *
_zip_readstr(unsigned char **buf, int len, int nulp, struct zip_error *error)
{
    char *r, *o;

    r = (char *)malloc(nulp ? len+1 : len);
    if (!r) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }
    
    memcpy(r, *buf, len);
    *buf += len;

    if (nulp) {
	/* replace any in-string NUL characters with spaces */
	r[len] = 0;
	for (o=r; o<r+len; o++)
	    if (*o == '\0')
		*o = ' ';
    }

    return r;
}



static void
_zip_write2(unsigned short i, FILE *fp)
{
    putc(i&0xff, fp);
    putc((i>>8)&0xff, fp);

    return;
}



static void
_zip_write4(unsigned int i, FILE *fp)
{
    putc(i&0xff, fp);
    putc((i>>8)&0xff, fp);
    putc((i>>16)&0xff, fp);
    putc((i>>24)&0xff, fp);
    
    return;
}



// modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
/*static*/ void
_zip_u2d_time(time_t time, unsigned short *dtime, unsigned short *ddate)
{
    struct tm *tm;

    tm = localtime(&time);
    *ddate = ((tm->tm_year+1900-1980)<<9) + ((tm->tm_mon+1)<<5)
	+ tm->tm_mday;
    *dtime = ((tm->tm_hour)<<11) + ((tm->tm_min)<<5)
	+ ((tm->tm_sec)>>1);

    return;
}
/*
  zip_entry_free.c -- free struct zip_entry
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



void
_zip_entry_free(struct zip_entry *ze)
{
    free(ze->ch_filename);
    ze->ch_filename = NULL;
    free(ze->ch_comment);
    ze->ch_comment = NULL;
    ze->ch_comment_len = -1;

    _zip_unchange_data(ze);
}
/*
  zip_entry_new.c -- create and init struct zip_entry
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



struct zip_entry *
_zip_entry_new(struct zip *za)
{
    struct zip_entry *ze;
    if (!za) {
	ze = (struct zip_entry *)malloc(sizeof(struct zip_entry));
	if (!ze) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    return NULL;
	}
    }
    else {
	if (za->nentry >= za->nentry_alloc-1) {
	    za->nentry_alloc += 16;
	    za->entry = (struct zip_entry *)realloc(za->entry,
						    sizeof(struct zip_entry)
						    * za->nentry_alloc);
	    if (!za->entry) {
		_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
		return NULL;
	    }
	}
	ze = za->entry+za->nentry;
    }

    ze->state = ZIP_ST_UNCHANGED;

    ze->ch_filename = NULL;
    ze->ch_comment = NULL;
    ze->ch_comment_len = -1;
    ze->source = NULL;

    if (za)
	za->nentry++;

    return ze;
}
/*
   This file was generated automatically by ./make_zip_err_str.sh
   from ./zip.h; make changes there.
 */

#include "zipint.h"



const char * const _zip_err_str[] = {
    "No error",
    "Multi-disk zip archives not supported",
    "Renaming temporary file failed",
    "Closing zip archive failed",
    "Seek error",
    "Read error",
    "Write error",
    "CRC error",
    "Containing zip archive was closed",
    "No such file",
    "File already exists",
    "Can't open file",
    "Failure to create temporary file",
    "Zlib error",
    "Malloc failure",
    "Entry has been changed",
    "Compression method not supported",
    "Premature EOF",
    "Invalid argument",
    "Not a zip archive",
    "Internal error",
    "Zip archive inconsistent",
    "Can't remove file",
    "Entry has been deleted",
};

const int _zip_nerr_str = sizeof(_zip_err_str)/sizeof(_zip_err_str[0]);

#define N ZIP_ET_NONE
#define S ZIP_ET_SYS
#define Z ZIP_ET_ZLIB

const int _zip_err_type[] = {
    N,
    N,
    S,
    S,
    S,
    S,
    S,
    N,
    N,
    N,
    N,
    S,
    S,
    Z,
    N,
    N,
    N,
    N,
    N,
    N,
    N,
    N,
    S,
    N,
};
/*
  zip_error.c -- struct zip_error helper functions
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



void
_zip_error_clear(struct zip_error *err)
{
    err->zip_err = ZIP_ER_OK;
    err->sys_err = 0;
}



void
_zip_error_copy(struct zip_error *dst, struct zip_error *src)
{
    dst->zip_err = src->zip_err;
    dst->sys_err = src->sys_err;
}



void
_zip_error_fini(struct zip_error *err)
{
    free(err->str);
    err->str = NULL;
}



void
_zip_error_get(struct zip_error *err, int *zep, int *sep)
{
    if (zep)
	*zep = err->zip_err;
    if (sep) {
	if (zip_error_get_sys_type(err->zip_err) != ZIP_ET_NONE)
	    *sep = err->sys_err;
	else
	    *sep = 0;
    }
}



void
_zip_error_init(struct zip_error *err)
{
    err->zip_err = ZIP_ER_OK;
    err->sys_err = 0;
    err->str = NULL;
}



void
_zip_error_set(struct zip_error *err, int ze, int se)
{
    if (err) {
	err->zip_err = ze;
	err->sys_err = se;
    }
}
/*
  zip_error_clear.c -- clear zip error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN void
zip_error_clear(struct zip *za)
{
    _zip_error_clear(&za->error);
}
/*
  zip_error_get.c -- get zip error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN void
zip_error_get(struct zip *za, int *zep, int *sep)
{
    _zip_error_get(&za->error, zep, sep);
}
/*
  zip_error_get_sys_type.c -- return type of system error code
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_error_get_sys_type(int ze)
{
    if (ze < 0 || ze >= _zip_nerr_str)
	return 0;

    return _zip_err_type[ze];
}
/*
  zip_error_sterror.c -- get string representation of struct zip_error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zipint.h"



const char *
_zip_error_strerror(struct zip_error *err)
{
    const char *zs, *ss;
    char buf[128], *s;

    _zip_error_fini(err);

    if (err->zip_err < 0 || err->zip_err >= _zip_nerr_str) {
	sprintf(buf, "Unknown error %d", err->zip_err);
	zs = NULL;
	ss = buf;
    }
    else {
	zs = _zip_err_str[err->zip_err];
	
	switch (_zip_err_type[err->zip_err]) {
	case ZIP_ET_SYS:
	    ss = strerror(err->sys_err);
	    break;

	case ZIP_ET_ZLIB:
	    ss = zError(err->sys_err);
	    break;

	default:
	    ss = NULL;
	}
    }

    if (ss == NULL)
	return zs;
    else {
	if ((s=(char *)malloc(strlen(ss)
			      + (zs ? strlen(zs)+2 : 0) + 1)) == NULL)
	    return _zip_err_str[ZIP_ER_MEMORY];
	
	sprintf(s, "%s%s%s",
		(zs ? zs : ""),
		(zs ? ": " : ""),
		ss);
	err->str = s;

	return s;
    }
}
/*
  zip_error_to_str.c -- get string representation of zip error code
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zipint.h"



ZIP_EXTERN int
zip_error_to_str(char *buf, size_t len, int ze, int se)
{
    const char *zs, *ss;

    if (ze < 0 || ze >= _zip_nerr_str)
	return snprintf(buf, len, "Unknown error %d", ze);

    zs = _zip_err_str[ze];
	
    switch (_zip_err_type[ze]) {
    case ZIP_ET_SYS:
	ss = strerror(se);
	break;
	
    case ZIP_ET_ZLIB:
	ss = zError(se);
	break;
	
    default:
	ss = NULL;
    }

    return snprintf(buf, len, "%s%s%s",
		    zs, (ss ? ": " : ""), (ss ? ss : ""));
}
/*
  zip_fclose.c -- close file in zip archive
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_fclose(struct zip_file *zf)
{
    int i, ret;
    
    if (zf->zstr)
	inflateEnd(zf->zstr);
    free(zf->buffer);
    free(zf->zstr);

    for (i=0; i<zf->za->nfile; i++) {
	if (zf->za->file[i] == zf) {
	    zf->za->file[i] = zf->za->file[zf->za->nfile-1];
	    zf->za->nfile--;
	    break;
	}
    }

    ret = 0;
    if (zf->error.zip_err)
	ret = zf->error.zip_err;
    else if ((zf->flags & ZIP_ZF_CRC) && (zf->flags & ZIP_ZF_EOF)) {
	/* if EOF, compare CRC */
	if (zf->crc_orig != zf->crc)
	    ret = ZIP_ER_CRC;
    }

    free(zf);
    return ret;
}
/*
  zip_file_error_clear.c -- clear zip file error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN void
zip_file_error_clear(struct zip_file *zf)
{
    _zip_error_clear(&zf->error);
}
/*
  zip_file_error_get.c -- get zip file error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN void
zip_file_error_get(struct zip_file *zf, int *zep, int *sep)
{
    _zip_error_get(&zf->error, zep, sep);
}
/*
  zip_file_get_offset.c -- get offset of file data in archive.
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "zipint.h"



/* _zip_file_get_offset(za, ze):
   Returns the offset of the file data for entry ze.

   On error, fills in za->error and returns 0.
*/

unsigned int
_zip_file_get_offset(struct zip *za, int idx)
{
    struct zip_dirent de;
    unsigned int offset;

    offset = za->cdir->entry[idx].offset;

    if (fseeko(za->zp, offset, SEEK_SET) != 0) {
	_zip_error_set(&za->error, ZIP_ER_SEEK, errno);
	return 0;
    }

    if (_zip_dirent_read(&de, za->zp, NULL, NULL, 1, &za->error) != 0)
	return 0;

    offset += LENTRYSIZE + de.filename_len + de.extrafield_len;

    _zip_dirent_finalize(&de);

    return offset;
}
/*
  zip_file_sterror.c -- get string representation of zip file error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN const char *
zip_file_strerror(struct zip_file *zf)
{
    return _zip_error_strerror(&zf->error);
}
/*
  zip_filerange_crc.c -- compute CRC32 for a range of a file
  Copyright (C) 2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdio.h>
#include <errno.h>

#include "zipint.h"




int
_zip_filerange_crc(FILE *fp, off_t start, off_t len, uLong *crcp,
		   struct zip_error *errp)
{
    Bytef buf[BUFSIZE];
    size_t n;

    *crcp = crc32(0L, Z_NULL, 0);

    if (fseeko(fp, start, SEEK_SET) != 0) {
	_zip_error_set(errp, ZIP_ER_SEEK, errno);
	return -1;
    }
    
    while (len > 0) {
	n = len > BUFSIZE ? BUFSIZE : len;
	if ((n=fread(buf, 1, n, fp)) <= 0) {
	    _zip_error_set(errp, ZIP_ER_READ, errno);
	    return -1;
	}

	*crcp = crc32(*crcp, buf, n);

	len-= n;
    }

    return 0;
}
/*
  zip_fopen.c -- open file in zip archive for reading
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN struct zip_file *
zip_fopen(struct zip *za, const char *fname, int flags)
{
    int idx;

    if ((idx=zip_name_locate(za, fname, flags)) < 0)
	return NULL;

    return zip_fopen_index(za, idx, flags);
}
/*
  zip_fopen_index.c -- open file in zip archive for reading by index
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "zipint.h"

static struct zip_file *_zip_file_new(struct zip *za);



ZIP_EXTERN struct zip_file *
zip_fopen_index(struct zip *za, int fileno, int flags)
{
    int len, ret;
    int zfflags;
    struct zip_file *zf;

    if ((fileno < 0) || (fileno >= za->nentry)) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((flags & ZIP_FL_UNCHANGED) == 0
	&& ZIP_ENTRY_DATA_CHANGED(za->entry+fileno)) {
	_zip_error_set(&za->error, ZIP_ER_CHANGED, 0);
	return NULL;
    }

    if (fileno >= za->cdir->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    zfflags = 0;
    switch (za->cdir->entry[fileno].comp_method) {
    case ZIP_CM_STORE:
	zfflags |= ZIP_ZF_CRC;
	break;

    case ZIP_CM_DEFLATE:
	if ((flags & ZIP_FL_COMPRESSED) == 0)
	    zfflags |= ZIP_ZF_CRC | ZIP_ZF_DECOMP;
	break;
    default:
	if ((flags & ZIP_FL_COMPRESSED) == 0) {
	    _zip_error_set(&za->error, ZIP_ER_COMPNOTSUPP, 0);
	    return NULL;
	}
	break;
    }

    zf = _zip_file_new(za);

    zf->flags = zfflags;
    /* zf->name = za->cdir->entry[fileno].filename; */
    zf->method = za->cdir->entry[fileno].comp_method;
    zf->bytes_left = za->cdir->entry[fileno].uncomp_size;
    zf->cbytes_left = za->cdir->entry[fileno].comp_size;
    zf->crc_orig = za->cdir->entry[fileno].crc;

    if ((zf->fpos=_zip_file_get_offset(za, fileno)) == 0) {
	zip_fclose(zf);
	return NULL;
    }
    
    if ((zf->flags & ZIP_ZF_DECOMP) == 0)
	zf->bytes_left = zf->cbytes_left;
    else {
	if ((zf->buffer=(char *)malloc(BUFSIZE)) == NULL) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    zip_fclose(zf);
	    return NULL;
	}

	len = _zip_file_fillbuf(zf->buffer, BUFSIZE, zf);
	if (len <= 0) {
	    _zip_error_copy(&za->error, &zf->error);
	    zip_fclose(zf);
	return NULL;
	}

	if ((zf->zstr = (z_stream *)malloc(sizeof(z_stream))) == NULL) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    zip_fclose(zf);
	    return NULL;
	}
	zf->zstr->zalloc = Z_NULL;
	zf->zstr->zfree = Z_NULL;
	zf->zstr->opaque = NULL;
	zf->zstr->next_in = (Bytef *)zf->buffer;
	zf->zstr->avail_in = len;
	
	/* negative value to tell zlib that there is no header */
	if ((ret=inflateInit2(zf->zstr, -MAX_WBITS)) != Z_OK) {
	    _zip_error_set(&za->error, ZIP_ER_ZLIB, ret);
	    zip_fclose(zf);
	    return NULL;
	}
    }
    
    return zf;
}



int
_zip_file_fillbuf(void *buf, size_t buflen, struct zip_file *zf)
{
    int i, j;

    if (zf->error.zip_err != ZIP_ER_OK)
	return -1;

    if ((zf->flags & ZIP_ZF_EOF) || zf->cbytes_left <= 0 || buflen <= 0)
	return 0;
    
    if (fseeko(zf->za->zp, zf->fpos, SEEK_SET) < 0) {
	_zip_error_set(&zf->error, ZIP_ER_SEEK, errno);
	return -1;
    }
    if (buflen < zf->cbytes_left)
	i = buflen;
    else
	i = zf->cbytes_left;

    j = fread(buf, 1, i, zf->za->zp);
    if (j == 0) {
	_zip_error_set(&zf->error, ZIP_ER_EOF, 0);
	j = -1;
    }
    else if (j < 0)
	_zip_error_set(&zf->error, ZIP_ER_READ, errno);
    else {
	zf->fpos += j;
	zf->cbytes_left -= j;
    }

    return j;	
}



static struct zip_file *
_zip_file_new(struct zip *za)
{
    struct zip_file *zf, **file;
    int n;

    if ((zf=(struct zip_file *)malloc(sizeof(struct zip_file))) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }
    
    if (za->nfile >= za->nfile_alloc-1) {
	n = za->nfile_alloc + 10;
	file = (struct zip_file **)realloc(za->file,
					   n*sizeof(struct zip_file *));
	if (file == NULL) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    free(zf);
	    return NULL;
	}
	za->nfile_alloc = n;
	za->file = file;
    }

    za->file[za->nfile++] = zf;

    zf->za = za;
    _zip_error_init(&zf->error);
    zf->flags = 0;
    zf->crc = crc32(0L, Z_NULL, 0);
    zf->crc_orig = 0;
    zf->method = -1;
    zf->bytes_left = zf->cbytes_left = 0;
    zf->fpos = 0;
    zf->buffer = NULL;
    zf->zstr = NULL;

    return zf;
}
/*
  zip_fread.c -- read from file
  Copyright (C) 1999-2009 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN ssize_t
zip_fread(struct zip_file *zf, void *outbuf, size_t toread)
{
    int ret;
    size_t out_before, len;
    int i;

    if (!zf)
	return -1;

    if (zf->error.zip_err != 0)
	return -1;

    if ((zf->flags & ZIP_ZF_EOF) || (toread == 0))
	return 0;

    if (zf->bytes_left == 0) {
	zf->flags |= ZIP_ZF_EOF;
	if (zf->flags & ZIP_ZF_CRC) {
	    if (zf->crc != zf->crc_orig) {
		_zip_error_set(&zf->error, ZIP_ER_CRC, 0);
		return -1;
	    }
	}
	return 0;
    }
    
    if ((zf->flags & ZIP_ZF_DECOMP) == 0) {
	ret = _zip_file_fillbuf(outbuf, toread, zf);
	if (ret > 0) {
	    if (zf->flags & ZIP_ZF_CRC)
		zf->crc = crc32(zf->crc, (Bytef *)outbuf, ret);
	    zf->bytes_left -= ret;
	}
	return ret;
    }
    
    zf->zstr->next_out = (Bytef *)outbuf;
    zf->zstr->avail_out = toread;
    out_before = zf->zstr->total_out;
    
    /* endless loop until something has been accomplished */
    for (;;) {
	ret = inflate(zf->zstr, Z_SYNC_FLUSH);

	switch (ret) {
	case Z_STREAM_END:
	    if (zf->zstr->total_out == out_before) {
		if (zf->crc != zf->crc_orig) {
		    _zip_error_set(&zf->error, ZIP_ER_CRC, 0);
		    return -1;
		}
		else
		    return 0;
	    }

	    /* fallthrough */

	case Z_OK:
	    len = zf->zstr->total_out - out_before;
	    if (len >= zf->bytes_left || len >= toread) {
		if (zf->flags & ZIP_ZF_CRC)
		    zf->crc = crc32(zf->crc, (Bytef *)outbuf, len);
		zf->bytes_left -= len;
	        return len;
	    }
	    break;

	case Z_BUF_ERROR:
	    if (zf->zstr->avail_in == 0) {
		i = _zip_file_fillbuf(zf->buffer, BUFSIZE, zf);
		if (i == 0) {
		    _zip_error_set(&zf->error, ZIP_ER_INCONS, 0);
		    return -1;
		}
		else if (i < 0)
		    return -1;
		zf->zstr->next_in = (Bytef *)zf->buffer;
		zf->zstr->avail_in = i;
		continue;
	    }
	    /* fallthrough */
	case Z_NEED_DICT:
	case Z_DATA_ERROR:
	case Z_STREAM_ERROR:
	case Z_MEM_ERROR:
	    _zip_error_set(&zf->error, ZIP_ER_ZLIB, ret);
	    return -1;
	}
    }
}
/*
  zip_free.c -- free struct zip
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



/* _zip_free:
   frees the space allocated to a zipfile struct, and closes the
   corresponding file. */

void
_zip_free(struct zip *za)
{
    int i;

    if (za == NULL)
	return;

    if (za->zn)
	free(za->zn);

    if (za->zp)
	fclose(za->zp);

    _zip_cdir_free(za->cdir);

    if (za->entry) {
	for (i=0; i<za->nentry; i++) {
	    _zip_entry_free(za->entry+i);
	}
	free(za->entry);
    }

    for (i=0; i<za->nfile; i++) {
	if (za->file[i]->error.zip_err == ZIP_ER_OK) {
	    _zip_error_set(&za->file[i]->error, ZIP_ER_ZIPCLOSED, 0);
	    za->file[i]->za = NULL;
	}
    }

    free(za->file);
    
    free(za);

    return;
}
/*
  zip_get_archive_comment.c -- get archive comment
  Copyright (C) 2006-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN const char *
zip_get_archive_comment(struct zip *za, int *lenp, int flags)
{
    if ((flags & ZIP_FL_UNCHANGED)
	|| (za->ch_comment_len == -1)) {
	if (za->cdir) {
	    if (lenp != NULL)
		*lenp = za->cdir->comment_len;
	    return za->cdir->comment;
	}
	else {
	    if (lenp != NULL)
		*lenp = -1;
	    return NULL;
	}
    }
    
    if (lenp != NULL)
	*lenp = za->ch_comment_len;
    return za->ch_comment;
}
/*
  zip_get_archive_flag.c -- get archive global flag
  Copyright (C) 2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_get_archive_flag(struct zip *za, int flag, int flags)
{
    int fl;

    fl = (flags & ZIP_FL_UNCHANGED) ? za->flags : za->ch_flags;

    return (fl & flag) ? 1 : 0;
}
/*
  zip_get_file_comment.c -- get file comment
  Copyright (C) 2006-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN const char *
zip_get_file_comment(struct zip *za, int idx, int *lenp, int flags)
{
    if (idx < 0 || idx >= za->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((flags & ZIP_FL_UNCHANGED)
	|| (za->entry[idx].ch_comment_len == -1)) {
	if (lenp != NULL)
	    *lenp = za->cdir->entry[idx].comment_len;
	return za->cdir->entry[idx].comment;
    }
    
    if (lenp != NULL)
	*lenp = za->entry[idx].ch_comment_len;
    return za->entry[idx].ch_comment;
}
/*
  zip_get_name.c -- get filename for a file in zip file
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN const char *
zip_get_name(struct zip *za, int idx, int flags)
{
    return _zip_get_name(za, idx, flags, &za->error);
}



const char *
_zip_get_name(struct zip *za, int idx, int flags, struct zip_error *error)
{
    if (idx < 0 || idx >= za->nentry) {
	_zip_error_set(error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((flags & ZIP_FL_UNCHANGED) == 0) {
	if (za->entry[idx].state == ZIP_ST_DELETED) {
	    _zip_error_set(error, ZIP_ER_DELETED, 0);
	    return NULL;
	}
	if (za->entry[idx].ch_filename)
	    return za->entry[idx].ch_filename;
    }

    if (za->cdir == NULL || idx >= za->cdir->nentry) {
	_zip_error_set(error, ZIP_ER_INVAL, 0);
	return NULL;
    }
    
    return za->cdir->entry[idx].filename;
}
/*
  zip_get_num_files.c -- get number of files in archive
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_get_num_files(struct zip *za)
{
    if (za == NULL)
	return -1;

    return za->nentry;
}
/*
  zip_memdup.c -- internal zip function, "strdup" with len
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>

#include "zipint.h"



void *
_zip_memdup(const void *mem, size_t len, struct zip_error *error)
{
    void *ret;

    ret = malloc(len);
    if (!ret) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    memcpy(ret, mem, len);

    return ret;
}
/*
  zip_name_locate.c -- get index by name
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <string.h>

#include "zipint.h"



ZIP_EXTERN int
zip_name_locate(struct zip *za, const char *fname, int flags)
{
    return _zip_name_locate(za, fname, flags, &za->error);
}



int
_zip_name_locate(struct zip *za, const char *fname, int flags,
		 struct zip_error *error)
{
    int (*cmp)(const char *, const char *);
    const char *fn, *p;
    int i, n;

    if (fname == NULL) {
	_zip_error_set(error, ZIP_ER_INVAL, 0);
	return -1;
    }
    
    cmp = (flags & ZIP_FL_NOCASE) ? strcasecmp : strcmp;

    n = (flags & ZIP_FL_UNCHANGED) ? za->cdir->nentry : za->nentry;
    for (i=0; i<n; i++) {
	if (flags & ZIP_FL_UNCHANGED)
	    fn = za->cdir->entry[i].filename;
	else
	    fn = _zip_get_name(za, i, flags, error);

	/* newly added (partially filled) entry */
	if (fn == NULL)
	    continue;
	
	if (flags & ZIP_FL_NODIR) {
	    p = strrchr(fn, '/');
	    if (p)
		fn = p+1;
	}

	if (cmp(fname, fn) == 0)
	    return i;
    }

    _zip_error_set(error, ZIP_ER_NOENT, 0);
    return -1;
}
/*
  zip_new.c -- create and init struct zip
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



/* _zip_new:
   creates a new zipfile struct, and sets the contents to zero; returns
   the new struct. */

struct zip *
_zip_new(struct zip_error *error)
{
    struct zip *za;

    za = (struct zip *)malloc(sizeof(struct zip));
    if (!za) {
	_zip_error_set(error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    za->zn = NULL;
    za->zp = NULL;
    _zip_error_init(&za->error);
    za->cdir = NULL;
    za->ch_comment = NULL;
    za->ch_comment_len = -1;
    za->nentry = za->nentry_alloc = 0;
    za->entry = NULL;
    za->nfile = za->nfile_alloc = 0;
    za->file = NULL;
    za->comp_level = Z_BEST_COMPRESSION;
    za->flags = za->ch_flags = 0;
    
    return za;
}
/*
  zip_open.c -- open zip archive
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zipint.h"

static void set_error(int *, struct zip_error *, int);
static struct zip *_zip_allocate_new(const char *, int *);
static int _zip_checkcons(FILE *, struct zip_cdir *, struct zip_error *);
static void _zip_check_torrentzip(struct zip *);
static struct zip_cdir *_zip_find_central_dir(FILE *, int, int *, off_t);
static int _zip_file_exists(const char *, int, int *);
static int _zip_headercomp(struct zip_dirent *, int,
			   struct zip_dirent *, int);
static unsigned char *_zip_memmem(const unsigned char *, int,
				  const unsigned char *, int);
static struct zip_cdir *_zip_readcdir(FILE *, unsigned char *, unsigned char *,
				 int, int, struct zip_error *);



ZIP_EXTERN struct zip *
zip_open(const char *fn, int flags, int *zep)
{
    FILE *fp;
    struct zip *za;
    struct zip_cdir *cdir;
    int i;
    off_t len;
    
    switch (_zip_file_exists(fn, flags, zep)) {
    case -1:
	return NULL;
    case 0:
	return _zip_allocate_new(fn, zep);
    default:
	break;
    }

    if ((fp=fopen(fn, "rb")) == NULL) {
	set_error(zep, NULL, ZIP_ER_OPEN);
	return NULL;
    }

    fseeko(fp, 0, SEEK_END);
    len = ftello(fp);

    /* treat empty files as empty archives */
    if (len == 0) {
	if ((za=_zip_allocate_new(fn, zep)) == NULL)
	    fclose(fp);
	else
	    za->zp = fp;
	return za;
    }

    cdir = _zip_find_central_dir(fp, flags, zep, len);
    if (cdir == NULL) {
	fclose(fp);
	return NULL;
    }

    if ((za=_zip_allocate_new(fn, zep)) == NULL) {
	_zip_cdir_free(cdir);
	fclose(fp);
	return NULL;
    }

    za->cdir = cdir;
    za->zp = fp;

    if ((za->entry=(struct zip_entry *)malloc(sizeof(*(za->entry))
					      * cdir->nentry)) == NULL) {
	set_error(zep, NULL, ZIP_ER_MEMORY);
	_zip_free(za);
	return NULL;
    }
    for (i=0; i<cdir->nentry; i++)
	_zip_entry_new(za);

    _zip_check_torrentzip(za);
    za->ch_flags = za->flags;

    return za;
}



static void
set_error(int *zep, struct zip_error *err, int ze)
{
    int se;

    if (err) {
	_zip_error_get(err, &ze, &se);
	if (zip_error_get_sys_type(ze) == ZIP_ET_SYS)
	    errno = se;
    }

    if (zep)
	*zep = ze;
}



/* _zip_readcdir:
   tries to find a valid end-of-central-directory at the beginning of
   buf, and then the corresponding central directory entries.
   Returns a struct zip_cdir which contains the central directory 
   entries, or NULL if unsuccessful. */

static struct zip_cdir *
_zip_readcdir(FILE *fp, unsigned char *buf, unsigned char *eocd, int buflen,
	      int flags, struct zip_error *error)
{
    struct zip_cdir *cd;
    unsigned char *cdp, **bufp;
    int i, comlen, nentry;
    unsigned int left;

    comlen = buf + buflen - eocd - EOCDLEN;
    if (comlen < 0) {
	/* not enough bytes left for comment */
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	return NULL;
    }

    /* check for end-of-central-dir magic */
    if (memcmp(eocd, EOCD_MAGIC, 4) != 0) {
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	return NULL;
    }

    if (memcmp(eocd+4, "\0\0\0\0", 4) != 0) {
	_zip_error_set(error, ZIP_ER_MULTIDISK, 0);
	return NULL;
    }

    cdp = eocd + 8;
    /* number of cdir-entries on this disk */
    i = _zip_read2(&cdp);
    /* number of cdir-entries */
    nentry = _zip_read2(&cdp);

    if ((cd=_zip_cdir_new(nentry, error)) == NULL)
	return NULL;

    cd->size = _zip_read4(&cdp);
    cd->offset = _zip_read4(&cdp);
    cd->comment = NULL;
    cd->comment_len = _zip_read2(&cdp);

    if ((comlen < cd->comment_len) || (cd->nentry != i)) {
	_zip_error_set(error, ZIP_ER_NOZIP, 0);
	free(cd);
	return NULL;
    }
    if ((flags & ZIP_CHECKCONS) && comlen != cd->comment_len) {
	_zip_error_set(error, ZIP_ER_INCONS, 0);
	free(cd);
	return NULL;
    }

    if (cd->comment_len) {
	if ((cd->comment=(char *)_zip_memdup(eocd+EOCDLEN,
					     cd->comment_len, error))
	    == NULL) {
	    free(cd);
	    return NULL;
	}
    }

    if (cd->size < (unsigned int)(eocd-buf)) {
	/* if buffer already read in, use it */
	cdp = eocd - cd->size;
	bufp = &cdp;
    }
    else {
	/* go to start of cdir and read it entry by entry */
	bufp = NULL;
	clearerr(fp);
	fseeko(fp, cd->offset, SEEK_SET);
	/* possible consistency check: cd->offset =
	   len-(cd->size+cd->comment_len+EOCDLEN) ? */
	if (ferror(fp) || ((unsigned long)ftello(fp) != cd->offset)) {
	    /* seek error or offset of cdir wrong */
	    if (ferror(fp))
		_zip_error_set(error, ZIP_ER_SEEK, errno);
	    else
		_zip_error_set(error, ZIP_ER_NOZIP, 0);
	    free(cd);
	    return NULL;
	}
    }

    left = cd->size;
    i=0;
    do {
	if (i == cd->nentry && left > 0) {
	    /* Infozip extension for more than 64k entries:
	       nentries wraps around, size indicates correct EOCD */
	    _zip_cdir_grow(cd, cd->nentry+0x10000, error);
	}

	if ((_zip_dirent_read(cd->entry+i, fp, bufp, &left, 0, error)) < 0) {
	    cd->nentry = i;
	    _zip_cdir_free(cd);
	    return NULL;
	}
	i++;
	
    } while (i<cd->nentry);
    
    return cd;
}



/* _zip_checkcons:
   Checks the consistency of the central directory by comparing central
   directory entries with local headers and checking for plausible
   file and header offsets. Returns -1 if not plausible, else the
   difference between the lowest and the highest fileposition reached */

static int
_zip_checkcons(FILE *fp, struct zip_cdir *cd, struct zip_error *error)
{
    int i;
    unsigned int min, max, j;
    struct zip_dirent temp;

    if (cd->nentry) {
	max = cd->entry[0].offset;
	min = cd->entry[0].offset;
    }
    else
	min = max = 0;

    for (i=0; i<cd->nentry; i++) {
	if (cd->entry[i].offset < min)
	    min = cd->entry[i].offset;
	if (min > cd->offset) {
	    _zip_error_set(error, ZIP_ER_NOZIP, 0);
	    return -1;
	}
	
	j = cd->entry[i].offset + cd->entry[i].comp_size
	    + cd->entry[i].filename_len + LENTRYSIZE;
	if (j > max)
	    max = j;
	if (max > cd->offset) {
	    _zip_error_set(error, ZIP_ER_NOZIP, 0);
	    return -1;
	}
	
	if (fseeko(fp, cd->entry[i].offset, SEEK_SET) != 0) {
	    _zip_error_set(error, ZIP_ER_SEEK, 0);
	    return -1;
	}
	
	if (_zip_dirent_read(&temp, fp, NULL, NULL, 1, error) == -1)
	    return -1;
	
	if (_zip_headercomp(cd->entry+i, 0, &temp, 1) != 0) {
	    _zip_error_set(error, ZIP_ER_INCONS, 0);
	    _zip_dirent_finalize(&temp);
	    return -1;
	}
	_zip_dirent_finalize(&temp);
    }

    return max - min;
}



/* _zip_check_torrentzip:
   check wether ZA has a valid TORRENTZIP comment, i.e. is torrentzipped */

static void
_zip_check_torrentzip(struct zip *za)
{
    uLong crc_got, crc_should;
    char buf[8+1];
    char *end;

    if (za->zp == NULL || za->cdir == NULL)
	return;

    if (za->cdir->comment_len != TORRENT_SIG_LEN+8
	|| strncmp(za->cdir->comment, TORRENT_SIG, TORRENT_SIG_LEN) != 0)
	return;

    memcpy(buf, za->cdir->comment+TORRENT_SIG_LEN, 8);
    buf[8] = '\0';
    errno = 0;
    crc_should = strtoul(buf, &end, 16);
    if ((crc_should == UINT_MAX && errno != 0) || (end && *end))
	return;

    if (_zip_filerange_crc(za->zp, za->cdir->offset, za->cdir->size,
			   &crc_got, NULL) < 0)
	return;

    if (crc_got == crc_should)
	za->flags |= ZIP_AFL_TORRENT;
}




/* _zip_headercomp:
   compares two headers h1 and h2; if they are local headers, set
   local1p or local2p respectively to 1, else 0. Return 0 if they
   are identical, -1 if not. */

static int
_zip_headercomp(struct zip_dirent *h1, int local1p, struct zip_dirent *h2,
	   int local2p)
{
    if ((h1->version_needed != h2->version_needed)
#if 0
	/* some zip-files have different values in local
	   and global headers for the bitflags */
	|| (h1->bitflags != h2->bitflags)
#endif
	|| (h1->comp_method != h2->comp_method)
	|| (h1->last_mod != h2->last_mod)
	|| (h1->filename_len != h2->filename_len)
	|| !h1->filename || !h2->filename
	|| strcmp(h1->filename, h2->filename))
	return -1;

    /* check that CRC and sizes are zero if data descriptor is used */
    if ((h1->bitflags & ZIP_GPBF_DATA_DESCRIPTOR) && local1p
	&& (h1->crc != 0
	    || h1->comp_size != 0
	    || h1->uncomp_size != 0))
	return -1;
    if ((h2->bitflags & ZIP_GPBF_DATA_DESCRIPTOR) && local2p
	&& (h2->crc != 0
	    || h2->comp_size != 0
	    || h2->uncomp_size != 0))
	return -1;
    
    /* check that CRC and sizes are equal if no data descriptor is used */
    if (((h1->bitflags & ZIP_GPBF_DATA_DESCRIPTOR) == 0 || local1p == 0)
	&& ((h2->bitflags & ZIP_GPBF_DATA_DESCRIPTOR) == 0 || local2p == 0)) {
	if ((h1->crc != h2->crc)
	    || (h1->comp_size != h2->comp_size)
	    || (h1->uncomp_size != h2->uncomp_size))
	    return -1;
    }
    
    if ((local1p == local2p)
	&& ((h1->extrafield_len != h2->extrafield_len)
	    || (h1->extrafield_len && h2->extrafield
		&& memcmp(h1->extrafield, h2->extrafield,
			  h1->extrafield_len))))
	return -1;

    /* if either is local, nothing more to check */
    if (local1p || local2p)
	return 0;

    if ((h1->version_madeby != h2->version_madeby)
	|| (h1->disk_number != h2->disk_number)
	|| (h1->int_attrib != h2->int_attrib)
	|| (h1->ext_attrib != h2->ext_attrib)
	|| (h1->offset != h2->offset)
	|| (h1->comment_len != h2->comment_len)
	|| (h1->comment_len && h2->comment
	    && memcmp(h1->comment, h2->comment, h1->comment_len)))
	return -1;

    return 0;
}



static struct zip *
_zip_allocate_new(const char *fn, int *zep)
{
    struct zip *za;
    struct zip_error error;

    if ((za=_zip_new(&error)) == NULL) {
	set_error(zep, &error, 0);
	return NULL;
    }
	
    za->zn = strdup(fn);
    if (!za->zn) {
	_zip_free(za);
	set_error(zep, NULL, ZIP_ER_MEMORY);
	return NULL;
    }
    return za;
}



static int
_zip_file_exists(const char *fn, int flags, int *zep)
{
    struct stat st;

    if (fn == NULL) {
	set_error(zep, NULL, ZIP_ER_INVAL);
	return -1;
    }
    
    if (stat(fn, &st) != 0) {
	if (flags & ZIP_CREATE)
	    return 0;
	else {
	    set_error(zep, NULL, ZIP_ER_OPEN);
	    return -1;
	}
    }
    // modified for Zip/Ruby by SUGAWARA Genki <sgwr_dts@yahoo.co.jp>
    else if ((flags & ZIP_CREATE) && (flags & ZIP_TRUNC)) {
        return 0;
    }
    else if ((flags & ZIP_EXCL)) {
	set_error(zep, NULL, ZIP_ER_EXISTS);
	return -1;
    }
    /* ZIP_CREATE gets ignored if file exists and not ZIP_EXCL,
       just like open() */

    return 1;
}



static struct zip_cdir *
_zip_find_central_dir(FILE *fp, int flags, int *zep, off_t len)
{
    struct zip_cdir *cdir, *cdirnew;
    unsigned char *buf, *match;
    int a, best, buflen, i;
    struct zip_error zerr;

    i = fseeko(fp, -(len < CDBUFSIZE ? len : CDBUFSIZE), SEEK_END);
    if (i == -1 && errno != EFBIG) {
	/* seek before start of file on my machine */
	set_error(zep, NULL, ZIP_ER_SEEK);
	return NULL;
    }

    /* 64k is too much for stack */
    if ((buf=(unsigned char *)malloc(CDBUFSIZE)) == NULL) {
	set_error(zep, NULL, ZIP_ER_MEMORY);
	return NULL;
    }

    clearerr(fp);
    buflen = fread(buf, 1, CDBUFSIZE, fp);

    if (ferror(fp)) {
	set_error(zep, NULL, ZIP_ER_READ);
	free(buf);
	return NULL;
    }
    
    best = -1;
    cdir = NULL;
    match = buf;
    _zip_error_set(&zerr, ZIP_ER_NOZIP, 0);

    while ((match=_zip_memmem(match, buflen-(match-buf)-18,
			      (const unsigned char *)EOCD_MAGIC, 4))!=NULL) {
	/* found match -- check, if good */
	/* to avoid finding the same match all over again */
	match++;
	if ((cdirnew=_zip_readcdir(fp, buf, match-1, buflen, flags,
				   &zerr)) == NULL)
	    continue;

	if (cdir) {
	    if (best <= 0)
		best = _zip_checkcons(fp, cdir, &zerr);
	    a = _zip_checkcons(fp, cdirnew, &zerr);
	    if (best < a) {
		_zip_cdir_free(cdir);
		cdir = cdirnew;
		best = a;
	    }
	    else
		_zip_cdir_free(cdirnew);
	}
	else {
	    cdir = cdirnew;
	    if (flags & ZIP_CHECKCONS)
		best = _zip_checkcons(fp, cdir, &zerr);
	    else
		best = 0;
	}
	cdirnew = NULL;
    }

    free(buf);
    
    if (best < 0) {
	set_error(zep, &zerr, 0);
	_zip_cdir_free(cdir);
	return NULL;
    }

    return cdir;
}



static unsigned char *
_zip_memmem(const unsigned char *big, int biglen, const unsigned char *little, 
       int littlelen)
{
    const unsigned char *p;
    
    if ((biglen < littlelen) || (littlelen == 0))
	return NULL;
    p = big-1;
    while ((p=(const unsigned char *)
	        memchr(p+1, little[0], (size_t)(big-(p+1)+biglen-littlelen+1)))
	   != NULL) {
	if (memcmp(p+1, little+1, littlelen-1)==0)
	    return (unsigned char *)p;
    }

    return NULL;
}
/*
  zip_rename.c -- rename file in zip archive
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <string.h>

#include "zipint.h"



ZIP_EXTERN int
zip_rename(struct zip *za, int idx, const char *name)
{
    const char *old_name;
    int old_is_dir, new_is_dir;
    
    if (idx >= za->nentry || idx < 0 || name[0] == '\0') {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if ((old_name=zip_get_name(za, idx, 0)) == NULL)
	return -1;
								    
    new_is_dir = (name[strlen(name)-1] == '/');
    old_is_dir = (old_name[strlen(old_name)-1] == '/');

    if (new_is_dir != old_is_dir) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    return _zip_set_name(za, idx, name);
}
/*
  zip_replace.c -- replace file via callback function
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_replace(struct zip *za, int idx, struct zip_source *source)
{
    if (idx < 0 || idx >= za->nentry || source == NULL) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if (_zip_replace(za, idx, NULL, source) == -1)
	return -1;

    return 0;
}




int
_zip_replace(struct zip *za, int idx, const char *name,
	     struct zip_source *source)
{
    if (idx == -1) {
	if (_zip_entry_new(za) == NULL)
	    return -1;

	idx = za->nentry - 1;
    }
    
    _zip_unchange_data(za->entry+idx);

    if (name && _zip_set_name(za, idx, name) != 0)
	return -1;
    
    za->entry[idx].state = ((za->cdir == NULL || idx >= za->cdir->nentry)
			    ? ZIP_ST_ADDED : ZIP_ST_REPLACED);
    za->entry[idx].source = source;

    return idx;
}
#ifdef _WIN32
__declspec(dllexport) void Init_zipruby(void);
#endif

#include "zip_ruby.h"
#include "zip_ruby_zip.h"
#include "zip_ruby_archive.h"
#include "zip_ruby_file.h"
#include "zip_ruby_stat.h"
#include "zip_ruby_error.h"

void Init_zipruby() {
  Init_zipruby_zip();
  Init_zipruby_archive();
  Init_zipruby_file();
  Init_zipruby_stat();
  Init_zipruby_error();
}
#include <errno.h>
#include <zlib.h>

#include "zip.h"
#include "zipint.h"
#include "zip_ruby.h"
#include "zip_ruby_archive.h"
#include "zip_ruby_zip_source_proc.h"
#include "zip_ruby_zip_source_io.h"
#include "tmpfile.h"
#include "ruby.h"
#ifndef RUBY_VM
#include "rubyio.h"
#endif

static VALUE zipruby_archive_alloc(VALUE klass);
static void zipruby_archive_mark(struct zipruby_archive *p);
static void zipruby_archive_free(struct zipruby_archive *p);
static VALUE zipruby_archive_s_open(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_s_open_buffer(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_s_decrypt(VALUE self, VALUE path, VALUE password);
static VALUE zipruby_archive_s_encrypt(VALUE self, VALUE path, VALUE password);
static VALUE zipruby_archive_close(VALUE self);
static VALUE zipruby_archive_num_files(VALUE self);
static VALUE zipruby_archive_get_name(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_fopen(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_get_stat(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_buffer(VALUE self, VALUE name, VALUE source);
static VALUE zipruby_archive_add_file(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_io(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_function(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_replace_buffer(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_replace_file(int argc, VALUE* argv, VALUE self);
static VALUE zipruby_archive_replace_io(int argc, VALUE* argv, VALUE self);
static VALUE zipruby_archive_replace_function(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_or_replace_buffer(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_or_replace_file(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_or_replace_io(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_add_or_replace_function(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_update(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_get_comment(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_set_comment(VALUE self, VALUE comment);
static VALUE zipruby_archive_locate_name(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_get_fcomment(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_archive_set_fcomment(VALUE self, VALUE index, VALUE comment);
static VALUE zipruby_archive_fdelete(VALUE self, VALUE index);
static VALUE zipruby_archive_frename(VALUE self, VALUE index, VALUE name);
static VALUE zipruby_archive_funchange(VALUE self, VALUE index);
static VALUE zipruby_archive_funchange_all(VALUE self);
static VALUE zipruby_archive_unchange(VALUE self);
static VALUE zipruby_archive_revert(VALUE self);
static VALUE zipruby_archive_each(VALUE self);
static VALUE zipruby_archive_commit(VALUE self);
static VALUE zipruby_archive_is_open(VALUE self);
static VALUE zipruby_archive_decrypt(VALUE self, VALUE password);
static VALUE zipruby_archive_encrypt(VALUE self, VALUE password);
static VALUE zipruby_archive_read(VALUE self);
static VALUE zipruby_archive_add_dir(VALUE self, VALUE name);

extern VALUE Zip;
VALUE Archive;
extern VALUE File;
extern VALUE Stat;
extern VALUE Error;

void Init_zipruby_archive() {
  Archive = rb_define_class_under(Zip, "Archive", rb_cObject);
  rb_define_alloc_func(Archive, zipruby_archive_alloc);
  rb_include_module(Archive, rb_mEnumerable);
  rb_define_singleton_method(Archive, "open", zipruby_archive_s_open, -1);
  rb_define_singleton_method(Archive, "open_buffer", zipruby_archive_s_open_buffer, -1);
  rb_define_singleton_method(Archive, "decrypt", zipruby_archive_s_decrypt, 2);
  rb_define_singleton_method(Archive, "encrypt", zipruby_archive_s_encrypt, 2);
  rb_define_method(Archive, "close", zipruby_archive_close, 0);
  rb_define_method(Archive, "num_files", zipruby_archive_num_files, 0);
  rb_define_method(Archive, "get_name", zipruby_archive_get_name, -1);
  rb_define_method(Archive, "fopen", zipruby_archive_fopen, -1);
  rb_define_method(Archive, "get_stat", zipruby_archive_get_stat, -1);
  rb_define_method(Archive, "add_buffer", zipruby_archive_add_buffer, 2);
  rb_define_method(Archive, "add_file", zipruby_archive_add_file, -1);
  rb_define_method(Archive, "add_io", zipruby_archive_add_io, -1);
  rb_define_method(Archive, "add", zipruby_archive_add_function, -1);
  rb_define_method(Archive, "replace_buffer", zipruby_archive_replace_buffer, -1);
  rb_define_method(Archive, "replace_file", zipruby_archive_replace_file, -1);
  rb_define_method(Archive, "replace_io", zipruby_archive_replace_io, -1);
  rb_define_method(Archive, "replace", zipruby_archive_replace_function, -1);
  rb_define_method(Archive, "add_or_replace_buffer", zipruby_archive_add_or_replace_buffer, -1);
  rb_define_method(Archive, "add_or_replace_file", zipruby_archive_add_or_replace_file, -1);
  rb_define_method(Archive, "add_or_replace_io", zipruby_archive_add_or_replace_io, -1);
  rb_define_method(Archive, "add_or_replace", zipruby_archive_add_or_replace_function, -1);
  rb_define_method(Archive, "update", zipruby_archive_update, -1);
  rb_define_method(Archive, "<<", zipruby_archive_add_io, -1);
  rb_define_method(Archive, "get_comment", zipruby_archive_get_comment, -1);
  rb_define_method(Archive, "comment", zipruby_archive_get_comment, -1);
  rb_define_method(Archive, "comment=", zipruby_archive_set_comment, 1);
  rb_define_method(Archive, "locate_name", zipruby_archive_locate_name, -1);
  rb_define_method(Archive, "get_fcomment", zipruby_archive_get_fcomment, -1);
  rb_define_method(Archive, "set_fcomment", zipruby_archive_set_fcomment, 2);
  rb_define_method(Archive, "fdelete", zipruby_archive_fdelete, 1);
  rb_define_method(Archive, "frename", zipruby_archive_frename, 2);
  rb_define_method(Archive, "funchange", zipruby_archive_funchange, 1);
  rb_define_method(Archive, "funchange_all", zipruby_archive_funchange_all, 0);
  rb_define_method(Archive, "unchange", zipruby_archive_unchange, 0);
  rb_define_method(Archive, "frevert", zipruby_archive_unchange, 1);
  rb_define_method(Archive, "revert", zipruby_archive_revert, 0);
  rb_define_method(Archive, "each", zipruby_archive_each, 0);
  rb_define_method(Archive, "commit", zipruby_archive_commit, 0);
  rb_define_method(Archive, "open?", zipruby_archive_is_open, 0);
  rb_define_method(Archive, "decrypt", zipruby_archive_decrypt, 1);
  rb_define_method(Archive, "encrypt", zipruby_archive_encrypt, 1);
  rb_define_method(Archive, "read", zipruby_archive_read, 0);
  rb_define_method(Archive, "add_dir", zipruby_archive_add_dir, 1);
}

static VALUE zipruby_archive_alloc(VALUE klass) {
  struct zipruby_archive *p = ALLOC(struct zipruby_archive);

  p->archive = NULL;
  p->path = Qnil;
  p->flags = 0;
  p->tmpfilnam = NULL;
  p->buffer = Qnil;
  p->sources = Qnil;

  return Data_Wrap_Struct(klass, zipruby_archive_mark, zipruby_archive_free, p);
}

static void zipruby_archive_mark(struct zipruby_archive *p) {
  rb_gc_mark(p->path);
  rb_gc_mark(p->buffer);
  rb_gc_mark(p->sources);
}

static void zipruby_archive_free(struct zipruby_archive *p) {
  if (p->tmpfilnam) {
    zipruby_rmtmp(p->tmpfilnam);
    free(p->tmpfilnam);
  }

  xfree(p);
}

/* */
static VALUE zipruby_archive_s_open(int argc, VALUE *argv, VALUE self) {
  VALUE path, flags, comp_level;
  VALUE archive;
  struct zipruby_archive *p_archive;
  int i_flags = 0;
  int errorp;
  int i_comp_level = Z_BEST_COMPRESSION;

  rb_scan_args(argc, argv, "12", &path, &flags, &comp_level);
  Check_Type(path, T_STRING);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  if (!NIL_P(comp_level)) {
    i_comp_level = NUM2INT(comp_level);

    if (i_comp_level != Z_DEFAULT_COMPRESSION && i_comp_level != Z_NO_COMPRESSION && (i_comp_level < Z_BEST_SPEED || Z_BEST_COMPRESSION < i_comp_level)) {
      rb_raise(rb_eArgError, "Wrong compression level %d", i_comp_level);
    }
  }

  archive = rb_funcall(Archive, rb_intern("new"), 0);
  Data_Get_Struct(archive, struct zipruby_archive, p_archive);

  if ((p_archive->archive = zip_open(RSTRING_PTR(path), i_flags, &errorp)) == NULL) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Open archive failed - %s: %s", RSTRING_PTR(path), errstr);
  }

  p_archive->archive->comp_level = i_comp_level;
  p_archive->path = path;
  p_archive->flags = i_flags;
  p_archive->sources = rb_ary_new();

  if (rb_block_given_p()) {
    VALUE retval;
    int status;

    retval = rb_protect(rb_yield, archive, &status);
    zipruby_archive_close(archive);

    if (status != 0) {
      rb_jump_tag(status);
    }

    return retval;
  } else {
    return archive;
  }
}

/* */
static VALUE zipruby_archive_s_open_buffer(int argc, VALUE *argv, VALUE self) {
  VALUE buffer, flags, comp_level;
  VALUE archive;
  struct zipruby_archive *p_archive;
  void *data = NULL;
  int len = 0, i_flags = 0;
  int errorp;
  int i_comp_level = Z_BEST_COMPRESSION;
  int buffer_is_temporary = 0;

  rb_scan_args(argc, argv, "03", &buffer, &flags, &comp_level);

  if (FIXNUM_P(buffer) && NIL_P(comp_level)) {
    comp_level = flags;
    flags = buffer;
    buffer = Qnil;
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  if (!NIL_P(comp_level)) {
    i_comp_level = NUM2INT(comp_level);

    if (i_comp_level != Z_DEFAULT_COMPRESSION && i_comp_level != Z_NO_COMPRESSION && (i_comp_level < Z_BEST_SPEED || Z_BEST_COMPRESSION < i_comp_level)) {
      rb_raise(rb_eArgError, "Wrong compression level %d", i_comp_level);
    }
  }

  if (i_flags & ZIP_CREATE) {
    if (!NIL_P(buffer)) {
      Check_Type(buffer, T_STRING);
    } else {
      buffer = rb_str_new("", 0);
      buffer_is_temporary = 1;
    }

    i_flags = (i_flags | ZIP_TRUNC);
  } else if (TYPE(buffer) == T_STRING) {
    data = RSTRING_PTR(buffer);
    len = RSTRING_LEN(buffer);
  } else if (rb_obj_is_instance_of(buffer, rb_cProc)) {
    data = (void *) buffer;
    len = -1;
  } else {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected String or Proc)", rb_class2name(CLASS_OF(buffer)));
  }

  archive = rb_funcall(Archive, rb_intern("new"), 0);
  Data_Get_Struct(archive, struct zipruby_archive, p_archive);

  if ((p_archive->tmpfilnam = zipruby_tmpnam(data, len)) == NULL) {
    rb_raise(Error, "Open archive failed: Failed to create temporary file");
  }

  if ((p_archive->archive = zip_open(p_archive->tmpfilnam, i_flags, &errorp)) == NULL) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Open archive failed: %s", errstr);
  }

  p_archive->archive->comp_level = i_comp_level;
  p_archive->path = rb_str_new2(p_archive->tmpfilnam);
  p_archive->flags = i_flags;
  p_archive->buffer = buffer;
  p_archive->sources = rb_ary_new();

  if (rb_block_given_p()) {
    VALUE retval;
    int status;

    retval = rb_protect(rb_yield, archive, &status);
    zipruby_archive_close(archive);

    if (status != 0) {
      rb_jump_tag(status);
    }

    return buffer_is_temporary ? buffer : retval;
  } else {
    return archive;
  }
}

/* */
static VALUE zipruby_archive_s_decrypt(VALUE self, VALUE path, VALUE password) {
  int res;
  int errorp, wrongpwd;
  long pwdlen;

  Check_Type(path, T_STRING);
  Check_Type(password, T_STRING);
  pwdlen = RSTRING_LEN(password);

  if (pwdlen < 1) {
    rb_raise(Error, "Decrypt archive failed - %s: Password is empty", RSTRING_PTR(path));
  } else if (pwdlen > 0xff) {
    rb_raise(Error, "Decrypt archive failed - %s: Password is too long", RSTRING_PTR(path));
  }

  res = zip_decrypt(RSTRING_PTR(path), RSTRING_PTR(password), pwdlen, &errorp, &wrongpwd);

  if (res == -1) {
    if (wrongpwd) {
      rb_raise(Error, "Decrypt archive failed - %s: Wrong password", RSTRING_PTR(path));
    } else {
      char errstr[ERRSTR_BUFSIZE];
      zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
      rb_raise(Error, "Decrypt archive failed - %s: %s", RSTRING_PTR(path), errstr);
    }
  }

  return (res > 0) ? Qtrue : Qfalse;
}

/* */
static VALUE zipruby_archive_s_encrypt(VALUE self, VALUE path, VALUE password) {
  int res;
  int errorp;
  long pwdlen;

  Check_Type(path, T_STRING);
  Check_Type(password, T_STRING);
  pwdlen = RSTRING_LEN(password);

  if (pwdlen < 1) {
    rb_raise(Error, "Encrypt archive failed - %s: Password is empty", RSTRING_PTR(path));
  } else if (pwdlen > 0xff) {
    rb_raise(Error, "Encrypt archive failed - %s: Password is too long", RSTRING_PTR(path));
  }

  res = zip_encrypt(RSTRING_PTR(path), RSTRING_PTR(password), pwdlen, &errorp);

  if (res == -1) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Encrypt archive failed - %s: %s", RSTRING_PTR(path), errstr);
  }

  return (res > 0) ? Qtrue : Qfalse;
}

/* */
static VALUE zipruby_archive_close(VALUE self) {
  struct zipruby_archive *p_archive;
  int changed, survivors;

  if (!zipruby_archive_is_open(self)) {
    return Qfalse;
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  changed = _zip_changed(p_archive->archive, &survivors);

  if (zip_close(p_archive->archive) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Close archive failed: %s", zip_strerror(p_archive->archive));
  }

  if (!NIL_P(p_archive->sources)){
    rb_ary_clear(p_archive->sources);
  }

  if (!NIL_P(p_archive->buffer) && changed) {
    rb_funcall(p_archive->buffer, rb_intern("replace"), 1, rb_funcall(self, rb_intern("read"), 0));
  }

  zipruby_rmtmp(p_archive->tmpfilnam);
  p_archive->archive = NULL;
  p_archive->flags = 0;

  return Qtrue;
}

/* */
static VALUE zipruby_archive_num_files(VALUE self) {
  struct zipruby_archive *p_archive;
  int num_files;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);
  num_files = zip_get_num_files(p_archive->archive);

  return INT2NUM(num_files);
}

/* */
static VALUE zipruby_archive_get_name(int argc, VALUE *argv, VALUE self) {
  VALUE index, flags;
  struct zipruby_archive *p_archive;
  int i_flags = 0;
  const char *name;

  rb_scan_args(argc, argv, "11", &index, &flags);
  Check_Type(index, T_FIXNUM);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if ((name = zip_get_name(p_archive->archive, NUM2INT(index), i_flags)) == NULL) {
    rb_raise(Error, "Get name failed at %d: %s", index, zip_strerror(p_archive->archive));
  }

  return (name != NULL) ? rb_str_new2(name) : Qnil;
}

/* */
static VALUE zipruby_archive_fopen(int argc, VALUE *argv, VALUE self) {
  VALUE index, flags, stat_flags, file;

  rb_scan_args(argc, argv, "12", &index, &flags, &stat_flags);
  file = rb_funcall(File, rb_intern("new"), 4, self, index, flags, stat_flags);

  if (rb_block_given_p()) {
    VALUE retval;
    int status;

    retval = rb_protect(rb_yield, file, &status);
    rb_funcall(file, rb_intern("close"), 0);

    if (status != 0) {
      rb_jump_tag(status);
    }

    return retval;
  } else {
    return file;
  }
}

/* */
static VALUE zipruby_archive_get_stat(int argc, VALUE *argv, VALUE self) {
  VALUE index, flags;

  rb_scan_args(argc, argv, "11", &index, &flags);

  return rb_funcall(Stat, rb_intern("new"), 3, self, index, flags);
}

/* */
static VALUE zipruby_archive_add_buffer(VALUE self, VALUE name, VALUE source) {
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  char *data;
  size_t len;

  Check_Type(name, T_STRING);
  Check_Type(source, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  len = RSTRING_LEN(source);

  if ((data = malloc(len)) == NULL) {
    rb_raise(rb_eRuntimeError, "Add file failed: Cannot allocate memory");
  }

  memset(data, 0, len);
  memcpy(data, RSTRING_PTR(source), len);

  if ((zsource = zip_source_buffer(p_archive->archive, data, len, 1)) == NULL) {
    free(data);
    rb_raise(Error, "Add file failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  if (zip_add(p_archive->archive, RSTRING_PTR(name), zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Add file failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_replace_buffer(int argc, VALUE *argv, VALUE self) {
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  VALUE index, source, flags;
  int i_index, i_flags = 0;
  char *data;
  size_t len;

  rb_scan_args(argc, argv, "21", &index, &source, &flags);

  if (TYPE(index) != T_STRING && !FIXNUM_P(index)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Fixnum or String)", rb_class2name(CLASS_OF(index)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(source, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (FIXNUM_P(index)) {
    i_index = NUM2INT(index);
  } else if ((i_index = zip_name_locate(p_archive->archive, RSTRING_PTR(index), i_flags)) == -1) {
    rb_raise(Error, "Replace file failed - %s: Archive does not contain a file", RSTRING_PTR(index));
  }

  len = RSTRING_LEN(source);

  if ((data = malloc(len)) == NULL) {
    rb_raise(rb_eRuntimeError, "Replace file failed: Cannot allocate memory");
  }

  memcpy(data, RSTRING_PTR(source), len);

  if ((zsource = zip_source_buffer(p_archive->archive, data, len, 1)) == NULL) {
    free(data);
    rb_raise(Error, "Replace file failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  if (zip_replace(p_archive->archive, i_index, zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Replace file failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_add_or_replace_buffer(int argc, VALUE *argv, VALUE self) {
  struct zipruby_archive *p_archive;
  VALUE name, source, flags;
  int index, i_flags = 0;

  rb_scan_args(argc, argv, "21", &name, &source, &flags);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  index = zip_name_locate(p_archive->archive, RSTRING_PTR(name), i_flags);

  if (index >= 0) {
    VALUE _args[] = { INT2NUM(index), source };
    return zipruby_archive_replace_buffer(2, _args, self);
  } else {
    return zipruby_archive_add_buffer(self, name, source);
  }
}

/* */
static VALUE zipruby_archive_add_file(int argc, VALUE *argv, VALUE self) {
  VALUE name, fname;
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;

  rb_scan_args(argc, argv, "11", &name, &fname);

  if (NIL_P(fname)) {
    fname = name;
    name = Qnil;
  }

  Check_Type(fname, T_STRING);

  if (NIL_P(name)) {
    name = rb_funcall(rb_cFile, rb_intern("basename"), 1, fname);
  }

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if ((zsource = zip_source_file(p_archive->archive, RSTRING_PTR(fname), 0, -1)) == NULL) {
    rb_raise(Error, "Add file failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  if (zip_add(p_archive->archive, RSTRING_PTR(name), zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Add file failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_replace_file(int argc, VALUE* argv, VALUE self) {
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  VALUE index, fname, flags;
  int i_index, i_flags = 0;

  rb_scan_args(argc, argv, "21", &index, &fname, &flags);

  if (TYPE(index) != T_STRING && !FIXNUM_P(index)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Fixnum or String)", rb_class2name(CLASS_OF(index)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(fname, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (FIXNUM_P(index)) {
    i_index = NUM2INT(index);
  } else if ((i_index = zip_name_locate(p_archive->archive, RSTRING_PTR(index), i_flags)) == -1) {
    rb_raise(Error, "Replace file failed - %s: Archive does not contain a file", RSTRING_PTR(index));
  }

  if ((zsource = zip_source_file(p_archive->archive, RSTRING_PTR(fname), 0, -1)) == NULL) {
    rb_raise(Error, "Replace file failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  if (zip_replace(p_archive->archive, i_index, zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Replace file failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_add_or_replace_file(int argc, VALUE *argv, VALUE self) {
  VALUE name, fname, flags;
  struct zipruby_archive *p_archive;
  int index, i_flags = 0;

  rb_scan_args(argc, argv, "12", &name, &fname, &flags);

  if (NIL_P(flags) && FIXNUM_P(fname)) {
    flags = fname;
    fname = Qnil;
  }

  if (NIL_P(fname)) {
    fname = name;
    name = Qnil;
  }

  Check_Type(fname, T_STRING);

  if (NIL_P(name)) {
    name = rb_funcall(rb_cFile, rb_intern("basename"), 1, fname);
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  index = zip_name_locate(p_archive->archive, RSTRING_PTR(name), i_flags);

  if (index >= 0) {
    VALUE _args[] = { INT2NUM(index), fname };
    return zipruby_archive_replace_file(2, _args, self);
  } else {
    VALUE _args[] = { name, fname };
    return zipruby_archive_add_file(2, _args, self);
  }
}

/* */
static VALUE zipruby_archive_add_io(int argc, VALUE *argv, VALUE self) {
  VALUE name, file, mtime;
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  struct read_io *z;

  rb_scan_args(argc, argv, "11", &name, &file);

  if (NIL_P(file)) {
    file = name;
    name = Qnil;
  }

  Check_IO(file);

  if (NIL_P(name)) {
    if (rb_obj_is_kind_of(file, rb_cFile)) {
      name = rb_funcall(rb_cFile, rb_intern("basename"), 1, rb_funcall(file, rb_intern("path"), 0));
    } else {
      rb_raise(rb_eRuntimeError, "Add io failed - %s: Entry name is not given", RSTRING(rb_inspect(file)));
    }
  }

  if (rb_obj_is_kind_of(file, rb_cFile)) {
    mtime = rb_funcall(file, rb_intern("mtime"), 0);
  } else {
    mtime = rb_funcall(rb_cTime, rb_intern("now"), 0);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive); 
  Check_Archive(p_archive);

  if ((z = malloc(sizeof(struct read_io))) == NULL) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(rb_eRuntimeError, "Add io failed - %s: Cannot allocate memory", RSTRING(rb_inspect(file)));
  }

  z->io = file;
  rb_ary_push(p_archive->sources, file);
  z->mtime = TIME2LONG(mtime);

  if ((zsource = zip_source_io(p_archive->archive, z)) == NULL) {
    free(z);
    rb_raise(Error, "Add io failed - %s: %s", RSTRING(rb_inspect(file)), zip_strerror(p_archive->archive));
  }

  if (zip_add(p_archive->archive, RSTRING_PTR(name), zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Add io failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_replace_io(int argc, VALUE *argv, VALUE self) {
  VALUE file, index, flags, mtime;
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  struct read_io *z;
  int i_index, i_flags = 0;

  rb_scan_args(argc, argv, "21", &index, &file, &flags);

  if (TYPE(index) != T_STRING && !FIXNUM_P(index)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Fixnum or String)", rb_class2name(CLASS_OF(index)));
  }

  Check_IO(file);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  if (rb_obj_is_kind_of(file, rb_cFile)) {
    mtime = rb_funcall(file, rb_intern("mtime"), 0);
  } else {
    mtime = rb_funcall(rb_cTime, rb_intern("now"), 0);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (FIXNUM_P(index)) {
    i_index = NUM2INT(index);
  } else if ((i_index = zip_name_locate(p_archive->archive, RSTRING_PTR(index), i_flags)) == -1) {
    rb_raise(Error, "Replace io failed - %s: Archive does not contain a file", RSTRING_PTR(index));
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive); 
  Check_Archive(p_archive);

  if ((z = malloc(sizeof(struct read_io))) == NULL) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(rb_eRuntimeError, "Replace io failed at %d - %s: Cannot allocate memory", i_index, RSTRING(rb_inspect(file)));
  }

  z->io = file;
  rb_ary_push(p_archive->sources, file);
  z->mtime = TIME2LONG(mtime);

  if ((zsource = zip_source_io(p_archive->archive, z)) == NULL) {
    free(z);
    rb_raise(Error, "Replace io failed at %d - %s: %s", i_index, RSTRING(rb_inspect(file)), zip_strerror(p_archive->archive));
  }

  if (zip_replace(p_archive->archive, i_index, zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Replace io failed at %d - %s: %s", i_index, RSTRING(rb_inspect(file)), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_add_or_replace_io(int argc, VALUE *argv, VALUE self) {
  VALUE name, io, flags;
  struct zipruby_archive *p_archive;
  int index, i_flags = 0;

  rb_scan_args(argc, argv, "21", &name, &io, &flags);
  Check_IO(io);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  index = zip_name_locate(p_archive->archive, RSTRING_PTR(name), i_flags);

  if (index >= 0) {
    VALUE _args[] = {INT2NUM(index), io, flags};
    return zipruby_archive_replace_io(2, _args, self);
  } else {
    VALUE _args[2] = { name, io };
    return zipruby_archive_add_io(2, _args, self);
  }
}

/* */
static VALUE zipruby_archive_add_function(int argc, VALUE *argv, VALUE self) {
  VALUE name, mtime;
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  struct read_proc *z;

  rb_scan_args(argc, argv, "11", &name, &mtime);
  rb_need_block();
  Check_Type(name, T_STRING);

  if (NIL_P(mtime)) {
    mtime = rb_funcall(rb_cTime, rb_intern("now"), 0);
  } else if (!rb_obj_is_instance_of(mtime, rb_cTime)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Time)", rb_class2name(CLASS_OF(mtime)));
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive); 
  Check_Archive(p_archive);

  if ((z = malloc(sizeof(struct read_proc))) == NULL) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(rb_eRuntimeError, "Add failed - %s: Cannot allocate memory", RSTRING_PTR(name));
  }

  z->proc = rb_block_proc();
  rb_ary_push(p_archive->sources, z->proc);
  z->mtime = TIME2LONG(mtime);

  if ((zsource = zip_source_proc(p_archive->archive, z)) == NULL) {
    free(z);
    rb_raise(Error, "Add failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  if (zip_add(p_archive->archive, RSTRING_PTR(name), zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Add file failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_replace_function(int argc, VALUE *argv, VALUE self) {
  VALUE index, flags, mtime;
  struct zipruby_archive *p_archive;
  struct zip_source *zsource;
  struct read_proc *z;
  int i_index, i_flags = 0;

  rb_scan_args(argc, argv, "12", &index, &mtime, &flags);
  rb_need_block();

  if (TYPE(index) != T_STRING && !FIXNUM_P(index)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Fixnum or String)", rb_class2name(CLASS_OF(index)));
  }

  if (NIL_P(mtime)) {
    mtime = rb_funcall(rb_cTime, rb_intern("now"), 0);
  } else if (!rb_obj_is_instance_of(mtime, rb_cTime)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Time)", rb_class2name(CLASS_OF(mtime)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive); 
  Check_Archive(p_archive);

  if (FIXNUM_P(index)) {
    i_index = NUM2INT(index);
  } else if ((i_index = zip_name_locate(p_archive->archive, RSTRING_PTR(index), i_flags)) == -1) {
    rb_raise(Error, "Replace file failed - %s: Archive does not contain a file", RSTRING_PTR(index));
  }

  if ((z = malloc(sizeof(struct read_proc))) == NULL) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(rb_eRuntimeError, "Replace failed at %d: Cannot allocate memory", i_index);
  }

  z->proc = rb_block_proc();
  rb_ary_push(p_archive->sources, z->proc);
  z->mtime = TIME2LONG(mtime);

  if ((zsource = zip_source_proc(p_archive->archive, z)) == NULL) {
    free(z);
    rb_raise(Error, "Replace failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  if (zip_replace(p_archive->archive, i_index, zsource) == -1) {
    zip_source_free(zsource);
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Replace failed at %d: %s", i_index, zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_add_or_replace_function(int argc, VALUE *argv, VALUE self) {
  VALUE name, mtime, flags;
  struct zipruby_archive *p_archive;
  int index, i_flags = 0;

  rb_scan_args(argc, argv, "12", &name, &mtime, &flags);

  if (NIL_P(flags) && FIXNUM_P(mtime)) {
    flags = mtime;
    mtime = Qnil;
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  index = zip_name_locate(p_archive->archive, RSTRING_PTR(name), i_flags);

  if (index >= 0) {
    VALUE _args[] = { INT2NUM(index), mtime };
    return zipruby_archive_replace_function(2, _args, self);
  } else {
    VALUE _args[] = { name, mtime };
    return zipruby_archive_add_function(2, _args, self);
  }
}

/* */
static VALUE zipruby_archive_update(int argc, VALUE *argv, VALUE self) {
  struct zipruby_archive *p_archive, *p_srcarchive;
  VALUE srcarchive, flags;
  int i, num_files, i_flags = 0;

  rb_scan_args(argc, argv, "11", &srcarchive, &flags);

  if (!rb_obj_is_instance_of(srcarchive, Archive)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected ZipRuby::Archive)", rb_class2name(CLASS_OF(srcarchive)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);
  Data_Get_Struct(srcarchive, struct zipruby_archive, p_srcarchive);
  Check_Archive(p_srcarchive);

  num_files = zip_get_num_files(p_srcarchive->archive);

  for (i = 0; i < num_files; i++) {
    struct zip_source *zsource;
    struct zip_file *fzip;
    struct zip_stat sb;
    char *buf;
    const char *name;
    int index, error;

    zip_stat_init(&sb);

    if (zip_stat_index(p_srcarchive->archive, i, 0, &sb)) {
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(Error, "Update archive failed: %s", zip_strerror(p_srcarchive->archive));
    }

    if ((buf = malloc(sb.size)) == NULL) {
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(rb_eRuntimeError, "Update archive failed: Cannot allocate memory");
    }

    fzip = zip_fopen_index(p_srcarchive->archive, i, 0);

    if (fzip == NULL) {
      free(buf);
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(Error, "Update archive failed: %s", zip_strerror(p_srcarchive->archive));
    }

    if (zip_fread(fzip, buf, sb.size) == -1) {
      free(buf);
      zip_fclose(fzip);
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(Error, "Update archive failed: %s", zip_file_strerror(fzip));
    }

    if ((error = zip_fclose(fzip)) != 0) {
      char errstr[ERRSTR_BUFSIZE];
      free(buf);
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      zip_error_to_str(errstr, ERRSTR_BUFSIZE, error, errno);
      rb_raise(Error, "Update archive failed: %s", errstr);
    }

    if ((zsource = zip_source_buffer(p_archive->archive, buf, sb.size, 1)) == NULL) {
      free(buf);
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(Error, "Update archive failed: %s", zip_strerror(p_archive->archive));
    }

    if ((name = zip_get_name(p_srcarchive->archive, i, 0)) == NULL) {
      zip_source_free(zsource);
      zip_unchange_all(p_archive->archive);
      zip_unchange_archive(p_archive->archive);
      rb_raise(Error, "Update archive failed: %s", zip_strerror(p_srcarchive->archive));
    }

    index = zip_name_locate(p_archive->archive, name, i_flags);

    if (index >= 0) {
      if (zip_replace(p_archive->archive, i, zsource) == -1) {
        zip_source_free(zsource);
        zip_unchange_all(p_archive->archive);
        zip_unchange_archive(p_archive->archive);
        rb_raise(Error, "Update archive failed: %s", zip_strerror(p_archive->archive));
      }
    } else {
      if (zip_add(p_archive->archive, name, zsource) == -1) {
        zip_source_free(zsource);
        zip_unchange_all(p_archive->archive);
        zip_unchange_archive(p_archive->archive);
        rb_raise(Error, "Update archive failed: %s", zip_strerror(p_archive->archive));
      }
    }
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_get_comment(int argc, VALUE *argv, VALUE self) {
  VALUE flags;
  struct zipruby_archive *p_archive;
  const char *comment;
  int lenp, i_flags = 0;

  rb_scan_args(argc, argv, "01", &flags);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  // XXX: How is the error checked?
  comment = zip_get_archive_comment(p_archive->archive, &lenp, i_flags);

  return comment ? rb_str_new(comment, lenp) : Qnil;
}

/* */
static VALUE zipruby_archive_set_comment(VALUE self, VALUE comment) {
  struct zipruby_archive *p_archive;
  const char *s_comment = NULL;
  int len = 0;

  if (!NIL_P(comment)) {
    Check_Type(comment, T_STRING);
    s_comment = RSTRING_PTR(comment);
    len = RSTRING_LEN(comment);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_set_archive_comment(p_archive->archive, s_comment, len) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Comment archived failed: %s", zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_locate_name(int argc, VALUE *argv, VALUE self) {
  VALUE fname, flags;
  struct zipruby_archive *p_archive;
  int i_flags = 0;

  rb_scan_args(argc, argv, "11", &fname, &flags);
  Check_Type(fname, T_STRING);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  return INT2NUM(zip_name_locate(p_archive->archive, RSTRING_PTR(fname), i_flags));
}

/* */
static VALUE zipruby_archive_get_fcomment(int argc, VALUE *argv, VALUE self) {
  VALUE index, flags;
  struct zipruby_archive *p_archive;
  const char *comment;
  int lenp, i_flags = 0;

  rb_scan_args(argc, argv, "11", &index, &flags);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  // XXX: How is the error checked?
  comment = zip_get_file_comment(p_archive->archive, NUM2INT(index), &lenp, i_flags);

  return comment ? rb_str_new(comment, lenp) : Qnil;
}

/* */
static VALUE zipruby_archive_set_fcomment(VALUE self, VALUE index, VALUE comment) {
  struct zipruby_archive *p_archive;
  char *s_comment = NULL;
  int len = 0;

  if (!NIL_P(comment)) {
    Check_Type(comment, T_STRING);
    s_comment = RSTRING_PTR(comment);
    len = RSTRING_LEN(comment);
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_set_file_comment(p_archive->archive, NUM2INT(index), s_comment, len) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Comment file failed at %d: %s", NUM2INT(index), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_fdelete(VALUE self, VALUE index) {
  struct zipruby_archive *p_archive;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_delete(p_archive->archive, NUM2INT(index)) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Delete file failed at %d: %s", NUM2INT(index), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_frename(VALUE self, VALUE index, VALUE name) {
  struct zipruby_archive *p_archive;

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_rename(p_archive->archive, NUM2INT(index), RSTRING_PTR(name)) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Rename file failed at %d: %s", NUM2INT(index), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_funchange(VALUE self, VALUE index) {
  struct zipruby_archive *p_archive;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_unchange(p_archive->archive, NUM2INT(index)) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Unchange file failed at %d: %s", NUM2INT(index), zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_funchange_all(VALUE self) {
  struct zipruby_archive *p_archive;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_unchange_all(p_archive->archive) == -1) {
    rb_raise(Error, "Unchange all file failed: %s", zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_unchange(VALUE self) {
  struct zipruby_archive *p_archive;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_unchange_archive(p_archive->archive) == -1) {
    rb_raise(Error, "Unchange archive failed: %s", zip_strerror(p_archive->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_revert(VALUE self) {
  zipruby_archive_funchange_all(self);
  zipruby_archive_unchange(self);

  return Qnil;
}

/* */
static VALUE zipruby_archive_each(VALUE self) {
  struct zipruby_archive *p_archive;
  int i, num_files;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);
  num_files = zip_get_num_files(p_archive->archive);

  for (i = 0; i < num_files; i++) {
    VALUE file;
    int status;

    file = rb_funcall(File, rb_intern("new"), 2, self, INT2NUM(i));
    rb_protect(rb_yield, file, &status);
    rb_funcall(file, rb_intern("close"), 0);

    if (status != 0) {
      rb_jump_tag(status);
    }
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_commit(VALUE self) {
  struct zipruby_archive *p_archive;
  int changed, survivors;
  int errorp;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  changed = _zip_changed(p_archive->archive, &survivors);

  if (zip_close(p_archive->archive) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Commit archive failed: %s", zip_strerror(p_archive->archive));
  }

  if (!NIL_P(p_archive->sources)){
    rb_ary_clear(p_archive->sources);
  }

  if (!NIL_P(p_archive->buffer) && changed) {
    rb_funcall(p_archive->buffer, rb_intern("replace"), 1, rb_funcall(self, rb_intern("read"), 0));
  }

  p_archive->archive = NULL;
  p_archive->flags = (p_archive->flags & ~(ZIP_CREATE | ZIP_EXCL));

  if ((p_archive->archive = zip_open(RSTRING_PTR(p_archive->path), p_archive->flags, &errorp)) == NULL) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Commit archive failed: %s", errstr);
  }

  return Qnil;
}

/* */
static VALUE zipruby_archive_is_open(VALUE self) {
  struct zipruby_archive *p_archive;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  return (p_archive->archive != NULL) ? Qtrue : Qfalse;
}

/* */
static VALUE zipruby_archive_decrypt(VALUE self, VALUE password) {
  VALUE retval;
  struct zipruby_archive *p_archive;
  long pwdlen;
  int changed, survivors;
  int errorp;

  Check_Type(password, T_STRING);
  pwdlen = RSTRING_LEN(password);

  if (pwdlen < 1) {
    rb_raise(Error, "Decrypt archive failed: Password is empty");
  } else if (pwdlen > 0xff) {
    rb_raise(Error, "Decrypt archive failed: Password is too long");
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  changed = _zip_changed(p_archive->archive, &survivors);

  if (zip_close(p_archive->archive) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Decrypt archive failed: %s", zip_strerror(p_archive->archive));
  }

  if (!NIL_P(p_archive->buffer) && changed) {
    rb_funcall(p_archive->buffer, rb_intern("replace"), 1, rb_funcall(self, rb_intern("read"), 0));
  }

  p_archive->archive = NULL;
  p_archive->flags = (p_archive->flags & ~(ZIP_CREATE | ZIP_EXCL));

  retval = zipruby_archive_s_decrypt(Archive, p_archive->path, password);

  if ((p_archive->archive = zip_open(RSTRING_PTR(p_archive->path), p_archive->flags, &errorp)) == NULL) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Decrypt archive failed: %s", errstr);
  }

  return retval;
}

/* */
static VALUE zipruby_archive_encrypt(VALUE self, VALUE password) {
  VALUE retval;
  struct zipruby_archive *p_archive;
  long pwdlen;
  int changed, survivors;
  int errorp;

  Check_Type(password, T_STRING);
  pwdlen = RSTRING_LEN(password);

  if (pwdlen < 1) {
    rb_raise(Error, "Encrypt archive failed: Password is empty");
  } else if (pwdlen > 0xff) {
    rb_raise(Error, "Encrypt archive failed: Password is too long");
  }

  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  changed = _zip_changed(p_archive->archive, &survivors);

  if (zip_close(p_archive->archive) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Encrypt archive failed: %s", zip_strerror(p_archive->archive));
  }

  if (!NIL_P(p_archive->buffer) && changed) {
    rb_funcall(p_archive->buffer, rb_intern("replace"), 1, rb_funcall(self, rb_intern("read"), 0));
  }

  p_archive->archive = NULL;
  p_archive->flags = (p_archive->flags & ~(ZIP_CREATE | ZIP_EXCL));

  retval = zipruby_archive_s_encrypt(Archive, p_archive->path, password);

  if ((p_archive->archive = zip_open(RSTRING_PTR(p_archive->path), p_archive->flags, &errorp)) == NULL) {
    char errstr[ERRSTR_BUFSIZE];
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, errorp, errno);
    rb_raise(Error, "Encrypt archive failed: %s", errstr);
  }

  return retval;
}

/* */
static VALUE zipruby_archive_read(VALUE self) {
  VALUE retval = Qnil;
  struct zipruby_archive *p_archive;
  FILE *fzip;
  char buf[DATA_BUFSIZE];
  ssize_t n;
  int block_given;

  Data_Get_Struct(self, struct zipruby_archive, p_archive);

  if (NIL_P(p_archive->path)) {
    rb_raise(rb_eRuntimeError, "invalid ZipRuby::Archive");
  }

#ifdef _WIN32
  if (fopen_s(&fzip, RSTRING_PTR(p_archive->path), "rb") != 0) {
    rb_raise(Error, "Read archive failed: Cannot open archive");
  }
#else
  if ((fzip = fopen(RSTRING_PTR(p_archive->path), "rb")) == NULL) {
    rb_raise(Error, "Read archive failed: Cannot open archive");
  }
#endif

  block_given = rb_block_given_p();

  while ((n = fread(buf, 1, sizeof(buf), fzip)) > 0) {
    if (block_given) {
      rb_yield(rb_str_new(buf, n));
    } else {
      if (NIL_P(retval)) {
        retval = rb_str_new(buf, n);
      } else {
        rb_str_buf_cat(retval, buf, n);
      }
    }
  }

#if defined(RUBY_VM) && defined(_WIN32)
  _fclose_nolock(fzip);
#elif defined(RUBY_WIN32_H)
#undef fclose
  fclose(fzip);
#define fclose(f) rb_w32_fclose(f)
#else
  fclose(fzip);
#endif

  if (n == -1) {
    rb_raise(Error, "Read archive failed");
  }

  return retval;
}

/* */
static VALUE zipruby_archive_add_dir(VALUE self, VALUE name) {
  struct zipruby_archive *p_archive;

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (zip_add_dir(p_archive->archive, RSTRING_PTR(name)) == -1) {
    zip_unchange_all(p_archive->archive);
    zip_unchange_archive(p_archive->archive);
    rb_raise(Error, "Add dir failed - %s: %s", RSTRING_PTR(name), zip_strerror(p_archive->archive));
  }

  return Qnil;
}
#include "zip_ruby.h"
#include "zip_ruby_error.h"
#include "ruby.h"

extern VALUE Zip;
VALUE Error;

void Init_zipruby_error() {
  Error = rb_define_class_under(Zip, "Error", rb_eStandardError);
}
#include <errno.h>

#include "zip.h"
#include "zipint.h"
#include "zip_ruby.h"
#include "zip_ruby_archive.h"
#include "zip_ruby_file.h"
#include "zip_ruby_stat.h"
#include "ruby.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static VALUE zipruby_file(VALUE klass);
static VALUE zipruby_file_alloc(VALUE klass);
static void zipruby_file_mark(struct zipruby_file *p);
static void zipruby_file_free(struct zipruby_file *p);
static VALUE zipruby_file_initialize(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_file_close(VALUE self);
static VALUE zipruby_file_read(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_file_stat(VALUE self);
static VALUE zipruby_file_get_comment(int argc, VALUE *argv, VALUE self);
static VALUE zipruby_file_set_comment(VALUE self, VALUE comment);
static VALUE zipruby_file_delete(VALUE self);
static VALUE zipruby_file_rename(VALUE self, VALUE name);
static VALUE zipruby_file_unchange(VALUE self);
static VALUE zipruby_file_name(VALUE self);
static VALUE zipruby_file_index(VALUE self);
static VALUE zipruby_file_crc(VALUE self);
static VALUE zipruby_file_size(VALUE self);
static VALUE zipruby_file_mtime(VALUE self);
static VALUE zipruby_file_comp_size(VALUE self);
static VALUE zipruby_file_comp_method(VALUE self);
static VALUE zipruby_file_encryption_method(VALUE self);
static VALUE zipruby_file_is_directory(VALUE self);

extern VALUE Zip;
extern VALUE Archive;
VALUE File;
extern VALUE Stat;
extern VALUE Error;

void Init_zipruby_file() {
  File = rb_define_class_under(Zip, "File", rb_cObject);
  rb_define_alloc_func(File, zipruby_file_alloc);
  rb_define_method(File, "initialize", zipruby_file_initialize, -1);
  rb_define_method(File, "close", zipruby_file_close, 0);
  rb_define_method(File, "read", zipruby_file_read, -1);
  rb_define_method(File, "stat", zipruby_file_stat, 0);
  rb_define_method(File, "get_comment", zipruby_file_get_comment, -1);
  rb_define_method(File, "comment", zipruby_file_get_comment, -1);
  rb_define_method(File, "comment=", zipruby_file_set_comment, 1);
  rb_define_method(File, "delete", zipruby_file_delete, 0);
  rb_define_method(File, "rename", zipruby_file_rename, 1);
  rb_define_method(File, "unchange", zipruby_file_unchange, 1);
  rb_define_method(File, "revert", zipruby_file_unchange, 1);
  rb_define_method(File, "name", zipruby_file_name, 0);
  rb_define_method(File, "index", zipruby_file_index, 0);
  rb_define_method(File, "crc", zipruby_file_crc, 0);
  rb_define_method(File, "size", zipruby_file_size, 0);
  rb_define_method(File, "mtime", zipruby_file_mtime, 0);
  rb_define_method(File, "comp_size", zipruby_file_comp_size, 0);
  rb_define_method(File, "comp_method", zipruby_file_comp_method, 0);
  rb_define_method(File, "encryption_method", zipruby_file_encryption_method, 0);
  rb_define_method(File, "directory?", zipruby_file_is_directory, 0);
}

static VALUE zipruby_file_alloc(VALUE klass) {
  struct zipruby_file *p = ALLOC(struct zipruby_file);

  p->archive = NULL;
  p->file = NULL;
  p->sb = NULL;

  return Data_Wrap_Struct(klass, zipruby_file_mark, zipruby_file_free, p);
}

static void zipruby_file_mark(struct zipruby_file *p) {
  if (p->archive) { rb_gc_mark(p->v_archive); }
  if (p->sb) { rb_gc_mark(p->v_sb); }
}

static void zipruby_file_free(struct zipruby_file *p) {
  xfree(p);
}

/* */
static VALUE zipruby_file_initialize(int argc, VALUE *argv, VALUE self) {
  VALUE archive, index, flags, stat_flags;
  struct zipruby_archive *p_archive;
  struct zipruby_file *p_file;
  struct zipruby_stat *p_stat;
  struct zip_file *fzip;
  char *fname = NULL;
  int i_index = -1, i_flags = 0;

  rb_scan_args(argc, argv, "22", &archive,  &index, &flags, &stat_flags);

  if (!rb_obj_is_instance_of(archive, Archive)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected ZipRuby::Archive)", rb_class2name(CLASS_OF(archive)));
  }

  switch (TYPE(index)) {
  case T_STRING: fname = RSTRING_PTR(index); break;
  case T_FIXNUM: i_index = NUM2INT(index); break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected String or Fixnum)", rb_class2name(CLASS_OF(index)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(archive, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);

  if (fname) {
    fzip = zip_fopen(p_archive->archive, fname, i_flags);

    if (fzip == NULL) {
      rb_raise(Error, "Open file failed - %s: %s", fname, zip_strerror(p_archive->archive));
    }
  } else {
    fzip = zip_fopen_index(p_archive->archive, i_index, i_flags);

    if (fzip == NULL) {
      rb_raise(Error, "Open file failed at %d: %s", i_index, zip_strerror(p_archive->archive));
    }
  }

  Data_Get_Struct(self, struct zipruby_file, p_file);
  p_file->v_archive = archive;
  p_file->archive = p_archive->archive;
  p_file->file = fzip;
  p_file->v_sb = rb_funcall(Stat, rb_intern("new"), 3, archive, index, stat_flags);
  Data_Get_Struct(p_file->v_sb, struct zipruby_stat, p_stat);
  p_file->sb = p_stat->sb;

  return Qnil;
}

/* */
static VALUE zipruby_file_close(VALUE self) {
  struct zipruby_file *p_file;
  int error;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  if ((error = zip_fclose(p_file->file)) != 0) {
    char errstr[ERRSTR_BUFSIZE];
    zip_unchange(p_file->archive, p_file->sb->index);
    zip_error_to_str(errstr, ERRSTR_BUFSIZE, error, errno);
    rb_raise(Error, "Close file failed: %s", errstr);
  }

  p_file->archive = NULL;
  p_file->file = NULL;
  p_file->sb = NULL;

  return Qnil;
}

/* */
static VALUE zipruby_file_read(int argc, VALUE *argv, VALUE self) {
  VALUE size, retval = Qnil;
  struct zipruby_file *p_file;
  struct zip_stat sb;
  int block_given;
  size_t bytes_left;
  char buf[DATA_BUFSIZE];
  ssize_t n;

  rb_scan_args(argc, argv, "01", &size);
  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);
  zip_stat_init(&sb);

  if (p_file->archive->cdir->entry[0].bitflags & ZIP_GPBF_ENCRYPTED) {
    rb_raise(Error, "Read file failed: File encrypted");
  }

  if (zip_stat_index(p_file->archive, p_file->sb->index, 0, &sb)) {
    rb_raise(Error, "Read file failed: %s", zip_strerror(p_file->archive));
  }

  if (NIL_P(size)) {
    bytes_left = sb.size;
  } else {
    bytes_left = NUM2LONG(size);
  }

  if (bytes_left <= 0) {
    return Qnil;
  }

  block_given = rb_block_given_p();

  while ((n = zip_fread(p_file->file, buf, MIN(bytes_left, sizeof(buf)))) > 0) {
    if (block_given) {
      rb_yield(rb_str_new(buf, n));
    } else {
      if (NIL_P(retval)) {
        retval = rb_str_new(buf, n);
      } else {
        rb_str_buf_cat(retval, buf, n);
      }
    }

    bytes_left -= n;
  }

  if (n == -1) {
    rb_raise(Error, "Read file failed: %s", zip_file_strerror(p_file->file));
  }

  return retval;
}

/* */
static VALUE zipruby_file_stat(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return p_file->v_sb;
}

/* */
static VALUE zipruby_file_get_comment(int argc, VALUE *argv, VALUE self) {
  VALUE flags;
  struct zipruby_file *p_file;
  const char *comment;
  int lenp, i_flags = 0;

  rb_scan_args(argc, argv, "01", &flags);

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  // XXX: How is the error checked?
  comment = zip_get_file_comment(p_file->archive, p_file->sb->index, &lenp, i_flags);

  return comment ? rb_str_new(comment, lenp) : Qnil;
}

/* */
static VALUE zipruby_file_set_comment(VALUE self, VALUE comment) {
  struct zipruby_file *p_file;
  char *s_comment = NULL;
  int len = 0;

  if (!NIL_P(comment)) {
    Check_Type(comment, T_STRING);
    s_comment = RSTRING_PTR(comment);
    len = RSTRING_LEN(comment);
  }

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  if (zip_set_file_comment(p_file->archive, p_file->sb->index, s_comment, len) == -1) {
    zip_unchange_all(p_file->archive);
    zip_unchange_archive(p_file->archive);
    rb_raise(Error, "Comment file failed - %s: %s", p_file->sb->name, zip_strerror(p_file->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_file_delete(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  if (zip_delete(p_file->archive, p_file->sb->index) == -1) {
    zip_unchange_all(p_file->archive);
    zip_unchange_archive(p_file->archive);
    rb_raise(Error, "Delete file failed - %s: %s", p_file->sb->name, zip_strerror(p_file->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_file_rename(VALUE self, VALUE name) {
  struct zipruby_file *p_file;

  Check_Type(name, T_STRING);
  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  if (zip_rename(p_file->archive, p_file->sb->index, RSTRING_PTR(name)) == -1) {
    zip_unchange_all(p_file->archive);
    zip_unchange_archive(p_file->archive);
    rb_raise(Error, "Rename file failed - %s: %s", p_file->sb->name, zip_strerror(p_file->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_file_unchange(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  if (zip_unchange(p_file->archive, p_file->sb->index) == -1) {
    rb_raise(Error, "Unchange file failed - %s: %s", p_file->sb->name, zip_strerror(p_file->archive));
  }

  return Qnil;
}

/* */
static VALUE zipruby_file_name(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_name(p_file->v_sb);
}

/* */
static VALUE zipruby_file_index(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_index(p_file->v_sb);
}

/* */
static VALUE zipruby_file_crc(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_crc(p_file->v_sb);
}

/* */
static VALUE zipruby_file_size(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_size(p_file->v_sb);
}

/* */
static VALUE zipruby_file_mtime(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_mtime(p_file->v_sb);
}

/* */
static VALUE zipruby_file_comp_size(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_comp_size(p_file->v_sb);
}

/* */
static VALUE zipruby_file_comp_method(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_comp_method(p_file->v_sb);
}

/* */
static VALUE zipruby_file_encryption_method(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_encryption_method(p_file->v_sb);
}

/* */
static VALUE zipruby_file_is_directory(VALUE self) {
  struct zipruby_file *p_file;

  Data_Get_Struct(self, struct zipruby_file, p_file);
  Check_File(p_file);

  return zipruby_stat_is_directory(p_file->v_sb);
}
#include <string.h>

#include "zip.h"
#include "zip_ruby.h"
#include "zip_ruby_archive.h"
#include "zip_ruby_stat.h"
#include "ruby.h"

static VALUE zipruby_stat_alloc(VALUE klass);
static void zipruby_stat_free(struct zipruby_stat *p);
static VALUE zipruby_stat_initialize(int argc, VALUE *argv, VALUE self);

extern VALUE Zip;
extern VALUE Archive;
VALUE Stat;
extern VALUE Error;

void Init_zipruby_stat() {
  Stat = rb_define_class_under(Zip, "Stat", rb_cObject);
  rb_define_alloc_func(Stat, zipruby_stat_alloc);
  rb_define_method(Stat, "initialize", zipruby_stat_initialize, -1);
  rb_define_method(Stat, "name", zipruby_stat_name, 0);
  rb_define_method(Stat, "index", zipruby_stat_index, 0);
  rb_define_method(Stat, "crc", zipruby_stat_crc, 0);
  rb_define_method(Stat, "size", zipruby_stat_size, 0);
  rb_define_method(Stat, "mtime", zipruby_stat_mtime, 0);
  rb_define_method(Stat, "comp_size", zipruby_stat_comp_size, 0);
  rb_define_method(Stat, "comp_method", zipruby_stat_comp_method, 0);
  rb_define_method(Stat, "encryption_method", zipruby_stat_encryption_method, 0);
  rb_define_method(Stat, "directory?", zipruby_stat_is_directory, 0);
}

static VALUE zipruby_stat_alloc(VALUE klass) {
  struct zipruby_stat *p = ALLOC(struct zipruby_stat);

  p->sb = ALLOC(struct zip_stat);
  zip_stat_init(p->sb);

  return Data_Wrap_Struct(klass, 0, zipruby_stat_free, p);
}

static void zipruby_stat_free(struct zipruby_stat *p) {
  xfree(p->sb);
  xfree(p);
}

/* */
static VALUE zipruby_stat_initialize(int argc, VALUE *argv, VALUE self) {
  VALUE archive, index, flags;
  struct zipruby_archive *p_archive;
  struct zipruby_stat *p_stat;
  char *fname = NULL;
  int i_index = -1, i_flags = 0;

  rb_scan_args(argc, argv, "21", &archive, &index, &flags);

  if (!rb_obj_is_instance_of(archive, Archive)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected ZipRuby::Archive)", rb_class2name(CLASS_OF(archive)));
  }

  switch (TYPE(index)) {
  case T_STRING: fname = RSTRING_PTR(index); break;
  case T_FIXNUM: i_index = NUM2INT(index); break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected String or Fixnum)", rb_class2name(CLASS_OF(index)));
  }

  if (!NIL_P(flags)) {
    i_flags = NUM2INT(flags);
  }

  Data_Get_Struct(archive, struct zipruby_archive, p_archive);
  Check_Archive(p_archive);
  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  if (fname) {
    if (zip_stat(p_archive->archive, fname, i_flags, p_stat->sb) != 0) {
      rb_raise(Error, "Obtain file status failed - %s: %s", fname, zip_strerror(p_archive->archive));
    }
  } else {
    if (zip_stat_index(p_archive->archive, i_index, i_flags, p_stat->sb) != 0) {
      rb_raise(Error, "Obtain file status failed at %d: %s", i_index, zip_strerror(p_archive->archive));
    }
  }

  return Qnil;
}

/* */
VALUE zipruby_stat_name(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return p_stat->sb->name ? rb_str_new2(p_stat->sb->name) : Qnil;
}

/* */
VALUE zipruby_stat_index(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return INT2NUM(p_stat->sb->index);
}

/* */
VALUE zipruby_stat_crc(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return UINT2NUM(p_stat->sb->crc);
}

/* */
VALUE zipruby_stat_size(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return LONG2NUM(p_stat->sb->size);
}

/* */
VALUE zipruby_stat_mtime(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return rb_funcall(rb_cTime, rb_intern("at"), 1,  LONG2NUM((long) p_stat->sb->mtime));
}

/* */
VALUE zipruby_stat_comp_size(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return LONG2NUM(p_stat->sb->comp_size);
}

/* */
VALUE zipruby_stat_comp_method(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return INT2NUM(p_stat->sb->comp_method);
}

/* */
VALUE zipruby_stat_encryption_method(VALUE self) {
  struct zipruby_stat *p_stat;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);

  return INT2NUM(p_stat->sb->encryption_method);
}

/* */
VALUE zipruby_stat_is_directory(VALUE self) {
  struct zipruby_stat *p_stat;
  const char *name;
  size_t name_len;
  off_t size;

  Data_Get_Struct(self, struct zipruby_stat, p_stat);
  name = p_stat->sb->name;
  size = p_stat->sb->size;

  if (!name || size != 0) {
    return Qfalse;
  }

  name_len = strlen(name);

  if (name_len > 0 && name[name_len - 1] == '/') {
    return Qtrue;
  } else {
    return Qfalse;
  }
}
#include <zlib.h>

#include "ruby.h"
#include "zip.h"
#include "zip_ruby.h"
#include "zip_ruby_zip.h"

VALUE Zip;

void Init_zipruby_zip() {
  Zip = rb_define_module("ZipRuby");
  rb_define_const(Zip, "VERSION", rb_str_new2(VERSION));

  rb_define_const(Zip, "CREATE",    INT2NUM(ZIP_CREATE));
  rb_define_const(Zip, "EXCL",      INT2NUM(ZIP_EXCL));
  rb_define_const(Zip, "CHECKCONS", INT2NUM(ZIP_CHECKCONS));
  rb_define_const(Zip, "TRUNC",     INT2NUM(ZIP_TRUNC));

  rb_define_const(Zip, "FL_NOCASE",     INT2NUM(ZIP_FL_NOCASE));
  rb_define_const(Zip, "FL_NODIR",      INT2NUM(ZIP_FL_NODIR));
  rb_define_const(Zip, "FL_COMPRESSED", INT2NUM(ZIP_FL_COMPRESSED));
  rb_define_const(Zip, "FL_UNCHANGED",  INT2NUM(ZIP_FL_UNCHANGED));

  rb_define_const(Zip, "CM_DEFAULT"   ,     INT2NUM(ZIP_CM_DEFAULT));
  rb_define_const(Zip, "CM_STORE",          INT2NUM(ZIP_CM_STORE));
  rb_define_const(Zip, "CM_SHRINK",         INT2NUM(ZIP_CM_SHRINK));
  rb_define_const(Zip, "CM_REDUCE_1",       INT2NUM(ZIP_CM_REDUCE_1));
  rb_define_const(Zip, "CM_REDUCE_2",       INT2NUM(ZIP_CM_REDUCE_2));
  rb_define_const(Zip, "CM_REDUCE_3",       INT2NUM(ZIP_CM_REDUCE_3));
  rb_define_const(Zip, "CM_REDUCE_4",       INT2NUM(ZIP_CM_REDUCE_4));
  rb_define_const(Zip, "CM_IMPLODE",        INT2NUM(ZIP_CM_IMPLODE));
  rb_define_const(Zip, "CM_DEFLATE",        INT2NUM(ZIP_CM_DEFLATE));
  rb_define_const(Zip, "CM_DEFLATE64",      INT2NUM(ZIP_CM_DEFLATE64));
  rb_define_const(Zip, "CM_PKWARE_IMPLODE", INT2NUM(ZIP_CM_PKWARE_IMPLODE));
  rb_define_const(Zip, "CM_BZIP2",          INT2NUM(ZIP_CM_BZIP2));

  rb_define_const(Zip, "EM_NONE",        INT2NUM(ZIP_EM_NONE));
  rb_define_const(Zip, "EM_TRAD_PKWARE", INT2NUM(ZIP_EM_TRAD_PKWARE));
  // XXX: Strong Encryption Header not parsed yet

  rb_define_const(Zip, "NO_COMPRESSION",      INT2NUM(Z_NO_COMPRESSION));
  rb_define_const(Zip, "BEST_SPEED",          INT2NUM(Z_BEST_SPEED));
  rb_define_const(Zip, "BEST_COMPRESSION",    INT2NUM(Z_BEST_COMPRESSION));
  rb_define_const(Zip, "DEFAULT_COMPRESSION", INT2NUM(Z_DEFAULT_COMPRESSION));
}
#include <string.h>

#include "zip.h"
#include "zipint.h"
#include "zip_ruby_zip_source_io.h"
#include "ruby.h"

#define IO_READ_BUFSIZE 8192

static VALUE io_read(VALUE io) {
  return rb_funcall(io, rb_intern("read"), 1, INT2FIX(IO_READ_BUFSIZE));
}

static ssize_t read_io(void *state, void *data, size_t len, enum zip_source_cmd cmd) {
  struct read_io *z;
  VALUE src;
  char *buf;
  size_t n;
  int status = 0;

  z = (struct read_io *) state;
  buf = (char *) data;

  switch (cmd) {
  case ZIP_SOURCE_OPEN:
    return 0;

  case ZIP_SOURCE_READ:
    src = rb_protect(io_read, z->io, NULL);

    if (status != 0) {
      VALUE message, clazz;

#if defined(RUBY_VM)
      message = rb_funcall(rb_errinfo(), rb_intern("message"), 0);
      clazz = CLASS_OF(rb_errinfo());
#else
      message = rb_funcall(ruby_errinfo, rb_intern("message"), 0);
      clazz = CLASS_OF(ruby_errinfo);
#endif

      rb_warn("Error in IO: %s (%s)", RSTRING_PTR(message), rb_class2name(clazz));
      return -1;
    }

    if (TYPE(src) != T_STRING) {
      return 0;
    }

    n = RSTRING_LEN(src);

    if (n > 0) {
      n = (n > len) ? len : n;
      memcpy(buf, RSTRING_PTR(src), n);
    }

    return n;

  case ZIP_SOURCE_CLOSE:
    return 0;

  case ZIP_SOURCE_STAT:
    {
      struct zip_stat *st = (struct zip_stat *)data;
      zip_stat_init(st);
      st->mtime = z->mtime;
      return sizeof(*st);
    }

  case ZIP_SOURCE_ERROR:
    return 0;

  case ZIP_SOURCE_FREE:
    free(z);
    return 0;
  }

  return -1;
}

struct zip_source *zip_source_io(struct zip *za, struct read_io *z) {
  struct zip_source *zs;
  zs = zip_source_function(za, read_io, z);
  return zs;
}
#include <string.h>

#include "zip.h"
#include "zipint.h"
#include "zip_ruby_zip_source_proc.h"
#include "ruby.h"

static VALUE proc_call(VALUE proc) {
  return rb_funcall(proc, rb_intern("call"), 0);
}

static ssize_t read_proc(void *state, void *data, size_t len, enum zip_source_cmd cmd) {
  struct read_proc *z;
  VALUE src;
  char *buf;
  size_t n;
  int status = 0;

  z = (struct read_proc *) state;
  buf = (char *) data;

  switch (cmd) {
  case ZIP_SOURCE_OPEN:
    return 0;

  case ZIP_SOURCE_READ:
    src = rb_protect(proc_call, z->proc, &status);

    if (status != 0) {
      VALUE message, clazz;

#if defined(RUBY_VM)
      message = rb_funcall(rb_errinfo(), rb_intern("message"), 0);
      clazz = CLASS_OF(rb_errinfo());
#else
      message = rb_funcall(ruby_errinfo, rb_intern("message"), 0);
      clazz = CLASS_OF(ruby_errinfo);
#endif

      rb_warn("Error in Proc: %s (%s)", RSTRING_PTR(message), rb_class2name(clazz));
      return -1;
    }


    if (TYPE(src) != T_STRING) {
      src = rb_funcall(src, rb_intern("to_s"), 0);
    }

    n = RSTRING_LEN(src);

    if (n > 0) {
      n = (n > len) ? len : n;
      memcpy(buf, RSTRING_PTR(src), n);
    }

    return n;

  case ZIP_SOURCE_CLOSE:
    return 0;

  case ZIP_SOURCE_STAT:
    {
      struct zip_stat *st = (struct zip_stat *)data;
      zip_stat_init(st);
      st->mtime = z->mtime;
      return sizeof(*st);
    }

  case ZIP_SOURCE_ERROR:
    return 0;

  case ZIP_SOURCE_FREE:
    free(z);
    return 0;
  }

  return -1;
}

struct zip_source *zip_source_proc(struct zip *za, struct read_proc *z) {
  struct zip_source *zs;
  zs = zip_source_function(za, read_proc, z);
  return zs;
}
/*
  zip_set_archive_comment.c -- set archive comment
  Copyright (C) 2006-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_set_archive_comment(struct zip *za, const char *comment, int len)
{
    char *tmpcom;

    if (len < 0 || len > MAXCOMLEN
	|| (len > 0 && comment == NULL)) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if (len > 0) {
	if ((tmpcom=(char *)_zip_memdup(comment, len, &za->error)) == NULL)
	    return -1;
    }
    else
	tmpcom = NULL;

    free(za->ch_comment);
    za->ch_comment = tmpcom;
    za->ch_comment_len = len;
    
    return 0;
}
/*
  zip_get_archive_flag.c -- set archive global flag
  Copyright (C) 2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_set_archive_flag(struct zip *za, int flag, int value)
{
    if (value)
	za->ch_flags |= flag;
    else
	za->ch_flags &= ~flag;

    return 0;
}
/*
  zip_set_file_comment.c -- set comment for file in archive
  Copyright (C) 2006-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_set_file_comment(struct zip *za, int idx, const char *comment, int len)
{
    char *tmpcom;

    if (idx < 0 || idx >= za->nentry
	|| len < 0 || len > MAXCOMLEN
	|| (len > 0 && comment == NULL)) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if (len > 0) {
	if ((tmpcom=(char *)_zip_memdup(comment, len, &za->error)) == NULL)
	    return -1;
    }
    else
	tmpcom = NULL;

    free(za->entry[idx].ch_comment);
    za->entry[idx].ch_comment = tmpcom;
    za->entry[idx].ch_comment_len = len;
    
    return 0;
}
/*
  zip_set_name.c -- rename helper function
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>
#include <string.h>

#include "zipint.h"



int
_zip_set_name(struct zip *za, int idx, const char *name)
{
    char *s;
    int i;
    
    if (idx < 0 || idx >= za->nentry || name == NULL) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if ((i=_zip_name_locate(za, name, 0, NULL)) != -1 && i != idx) {
	_zip_error_set(&za->error, ZIP_ER_EXISTS, 0);
	return -1;
    }

    /* no effective name change */
    if (i == idx)
	return 0;
    
    if ((s=strdup(name)) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return -1;
    }
    
    if (za->entry[idx].state == ZIP_ST_UNCHANGED) 
	za->entry[idx].state = ZIP_ST_RENAMED;

    free(za->entry[idx].ch_filename);
    za->entry[idx].ch_filename = s;

    return 0;
}
/*
  zip_source_buffer.c -- create zip data source from buffer
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>
#include <string.h>

#include "zipint.h"

struct read_data {
    const char *buf, *data, *end;
    time_t mtime;
    int freep;
};

static ssize_t read_data(void *state, void *data, size_t len,
			 enum zip_source_cmd cmd);



ZIP_EXTERN struct zip_source *
zip_source_buffer(struct zip *za, const void *data, off_t len, int freep)
{
    struct read_data *f;
    struct zip_source *zs;

    if (za == NULL)
	return NULL;

    if (len < 0 || (data == NULL && len > 0)) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((f=(struct read_data *)malloc(sizeof(*f))) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    f->data = (const char *)data;
    f->end = ((const char *)data)+len;
    f->freep = freep;
    f->mtime = time(NULL);
    
    if ((zs=zip_source_function(za, read_data, f)) == NULL) {
	free(f);
	return NULL;
    }

    return zs;
}



static ssize_t
read_data(void *state, void *data, size_t len, enum zip_source_cmd cmd)
{
    struct read_data *z;
    char *buf;
    size_t n;

    z = (struct read_data *)state;
    buf = (char *)data;

    switch (cmd) {
    case ZIP_SOURCE_OPEN:
	z->buf = z->data;
	return 0;
	
    case ZIP_SOURCE_READ:
	n = z->end - z->buf;
	if (n > len)
	    n = len;

	if (n) {
	    memcpy(buf, z->buf, n);
	    z->buf += n;
	}

	return n;
	
    case ZIP_SOURCE_CLOSE:
	return 0;

    case ZIP_SOURCE_STAT:
        {
	    struct zip_stat *st;
	    
	    if (len < sizeof(*st))
		return -1;

	    st = (struct zip_stat *)data;

	    zip_stat_init(st);
	    st->mtime = z->mtime;
	    st->size = z->end - z->data;
	    
	    return sizeof(*st);
	}

    case ZIP_SOURCE_ERROR:
	{
	    int *e;

	    if (len < sizeof(int)*2)
		return -1;

	    e = (int *)data;
	    e[0] = e[1] = 0;
	}
	return sizeof(int)*2;

    case ZIP_SOURCE_FREE:
	if (z->freep) {
	    free((void *)z->data);
	    z->data = NULL;
	}
	free(z);
	return 0;

    default:
	;
    }

    return -1;
}
/*
  zip_source_file.c -- create data source from file
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <errno.h>
#include <stdio.h>

#include "zipint.h"



ZIP_EXTERN struct zip_source *
zip_source_file(struct zip *za, const char *fname, off_t start, off_t len)
{
    if (za == NULL)
	return NULL;

    if (fname == NULL || start < 0 || len < -1) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    return _zip_source_file_or_p(za, fname, NULL, start, len);
}
/*
  zip_source_filep.c -- create data source from FILE *
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zipint.h"

struct read_file {
    char *fname;	/* name of file to copy from */
    FILE *f;		/* file to copy from */
    off_t off;		/* start offset of */
    off_t len;		/* lengt of data to copy */
    off_t remain;	/* bytes remaining to be copied */
    int e[2];		/* error codes */
};

static ssize_t read_file(void *state, void *data, size_t len,
		     enum zip_source_cmd cmd);



ZIP_EXTERN struct zip_source *
zip_source_filep(struct zip *za, FILE *file, off_t start, off_t len)
{
    if (za == NULL)
	return NULL;

    if (file == NULL || start < 0 || len < -1) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    return _zip_source_file_or_p(za, NULL, file, start, len);
}



struct zip_source *
_zip_source_file_or_p(struct zip *za, const char *fname, FILE *file,
		      off_t start, off_t len)
{
    struct read_file *f;
    struct zip_source *zs;

    if (file == NULL && fname == NULL) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((f=(struct read_file *)malloc(sizeof(struct read_file))) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    f->fname = NULL;
    if (fname) {
	if ((f->fname=strdup(fname)) == NULL) {
	    _zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	    free(f);
	    return NULL;
	}
    }
    f->f = file;
    f->off = start;
    f->len = (len ? len : -1);
    
    if ((zs=zip_source_function(za, read_file, f)) == NULL) {
	free(f);
	return NULL;
    }

    return zs;
}



static ssize_t
read_file(void *state, void *data, size_t len, enum zip_source_cmd cmd)
{
    struct read_file *z;
    char *buf;
    int i, n;

    z = (struct read_file *)state;
    buf = (char *)data;

    switch (cmd) {
    case ZIP_SOURCE_OPEN:
	if (z->fname) {
	    if ((z->f=fopen(z->fname, "rb")) == NULL) {
		z->e[0] = ZIP_ER_OPEN;
		z->e[1] = errno;
		return -1;
	    }
	}

	if (fseeko(z->f, z->off, SEEK_SET) < 0) {
	    z->e[0] = ZIP_ER_SEEK;
	    z->e[1] = errno;
	    return -1;
	}
	z->remain = z->len;
	return 0;
	
    case ZIP_SOURCE_READ:
	if (z->remain != -1)
	    n = len > z->remain ? z->remain : len;
	else
	    n = len;
	
	if ((i=fread(buf, 1, n, z->f)) < 0) {
	    z->e[0] = ZIP_ER_READ;
	    z->e[1] = errno;
	    return -1;
	}

	if (z->remain != -1)
	    z->remain -= i;

	return i;
	
    case ZIP_SOURCE_CLOSE:
	if (z->fname) {
	    fclose(z->f);
	    z->f = NULL;
	}
	return 0;

    case ZIP_SOURCE_STAT:
        {
	    struct zip_stat *st;
	    struct stat fst;
	    int err;
	    
	    if (len < sizeof(*st))
		return -1;

	    if (z->f)
		err = fstat(fileno(z->f), &fst);
	    else
		err = stat(z->fname, &fst);

	    if (err != 0) {
		z->e[0] = ZIP_ER_READ; /* best match */
		z->e[1] = errno;
		return -1;
	    }

	    st = (struct zip_stat *)data;

	    zip_stat_init(st);
	    st->mtime = fst.st_mtime;
	    if (z->len != -1)
		st->size = z->len;
	    else if ((fst.st_mode&S_IFMT) == S_IFREG)
		st->size = fst.st_size;

	    return sizeof(*st);
	}

    case ZIP_SOURCE_ERROR:
	if (len < sizeof(int)*2)
	    return -1;

	memcpy(data, z->e, sizeof(int)*2);
	return sizeof(int)*2;

    case ZIP_SOURCE_FREE:
	free(z->fname);
	if (z->f)
	    fclose(z->f);
	free(z);
	return 0;

    default:
	;
    }

    return -1;
}
/*
  zip_source_free.c -- free zip data source
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN void
zip_source_free(struct zip_source *source)
{
    if (source == NULL)
	return;

    (void)source->f(source->ud, NULL, 0, ZIP_SOURCE_FREE);

    free(source);
}
/*
  zip_source_function.c -- create zip data source from callback function
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN struct zip_source *
zip_source_function(struct zip *za, zip_source_callback zcb, void *ud)
{
    struct zip_source *zs;

    if (za == NULL)
	return NULL;

    if ((zs=(struct zip_source *)malloc(sizeof(*zs))) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    zs->f = zcb;
    zs->ud = ud;
    
    return zs;
}
/*
  zip_source_zip.c -- create data source from zip file
  Copyright (C) 1999-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>
#include <string.h>

#include "zipint.h"

struct read_zip {
    struct zip_file *zf;
    struct zip_stat st;
    off_t off, len;
};

static ssize_t read_zip(void *st, void *data, size_t len,
			enum zip_source_cmd cmd);



ZIP_EXTERN struct zip_source *
zip_source_zip(struct zip *za, struct zip *srcza, int srcidx, int flags,
	       off_t start, off_t len)
{
    struct zip_error error;
    struct zip_source *zs;
    struct read_zip *p;

    /* XXX: ZIP_FL_RECOMPRESS */

    if (za == NULL)
	return NULL;

    if (srcza == NULL || start < 0 || len < -1 || srcidx < 0 || srcidx >= srcza->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if ((flags & ZIP_FL_UNCHANGED) == 0
	&& ZIP_ENTRY_DATA_CHANGED(srcza->entry+srcidx)) {
	_zip_error_set(&za->error, ZIP_ER_CHANGED, 0);
	return NULL;
    }

    if (len == 0)
	len = -1;

    if (start == 0 && len == -1 && (flags & ZIP_FL_RECOMPRESS) == 0)
	flags |= ZIP_FL_COMPRESSED;
    else
	flags &= ~ZIP_FL_COMPRESSED;

    if ((p=(struct read_zip *)malloc(sizeof(*p))) == NULL) {
	_zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }
	
    _zip_error_copy(&error, &srcza->error);
	
    if (zip_stat_index(srcza, srcidx, flags, &p->st) < 0
	|| (p->zf=zip_fopen_index(srcza, srcidx, flags)) == NULL) {
	free(p);
	_zip_error_copy(&za->error, &srcza->error);
	_zip_error_copy(&srcza->error, &error);
	
	return NULL;
    }
    p->off = start;
    p->len = len;

    if ((flags & ZIP_FL_COMPRESSED) == 0) {
	p->st.size = p->st.comp_size = len;
	p->st.comp_method = ZIP_CM_STORE;
	p->st.crc = 0;
    }
    
    if ((zs=zip_source_function(za, read_zip, p)) == NULL) {
	free(p);
	return NULL;
    }

    return zs;
}



static ssize_t
read_zip(void *state, void *data, size_t len, enum zip_source_cmd cmd)
{
    struct read_zip *z;
    char b[8192], *buf;
    int i, n;

    z = (struct read_zip *)state;
    buf = (char *)data;

    switch (cmd) {
    case ZIP_SOURCE_OPEN:
	for (n=0; n<z->off; n+= i) {
	    i = (z->off-n > sizeof(b) ? sizeof(b) : z->off-n);
	    if ((i=zip_fread(z->zf, b, i)) < 0) {
		zip_fclose(z->zf);
		z->zf = NULL;
		return -1;
	    }
	}
	return 0;
	
    case ZIP_SOURCE_READ:
	if (z->len != -1)
	    n = len > z->len ? z->len : len;
	else
	    n = len;
	

	if ((i=zip_fread(z->zf, buf, n)) < 0)
	    return -1;

	if (z->len != -1)
	    z->len -= i;

	return i;
	
    case ZIP_SOURCE_CLOSE:
	return 0;

    case ZIP_SOURCE_STAT:
	if (len < sizeof(z->st))
	    return -1;
	len = sizeof(z->st);

	memcpy(data, &z->st, len);
	return len;

    case ZIP_SOURCE_ERROR:
	{
	    int *e;

	    if (len < sizeof(int)*2)
		return -1;

	    e = (int *)data;
	    zip_file_error_get(z->zf, e, e+1);
	}
	return sizeof(int)*2;

    case ZIP_SOURCE_FREE:
	zip_fclose(z->zf);
	free(z);
	return 0;

    default:
	;
    }

    return -1;
}
/*
  zip_stat.c -- get information about file by name
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_stat(struct zip *za, const char *fname, int flags, struct zip_stat *st)
{
    int idx;

    if ((idx=zip_name_locate(za, fname, flags)) < 0)
	return -1;

    return zip_stat_index(za, idx, flags, st);
}
/*
  zip_stat_index.c -- get information about file by index
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN int
zip_stat_index(struct zip *za, int index, int flags, struct zip_stat *st)
{
    const char *name;
    
    if (index < 0 || index >= za->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if ((name=zip_get_name(za, index, flags)) == NULL)
	return -1;
    

    if ((flags & ZIP_FL_UNCHANGED) == 0
	&& ZIP_ENTRY_DATA_CHANGED(za->entry+index)) {
	if (za->entry[index].source->f(za->entry[index].source->ud,
				     st, sizeof(*st), ZIP_SOURCE_STAT) < 0) {
	    _zip_error_set(&za->error, ZIP_ER_CHANGED, 0);
	    return -1;
	}
    }
    else {
	if (za->cdir == NULL || index >= za->cdir->nentry) {
	    _zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	    return -1;
	}
	
	st->crc = za->cdir->entry[index].crc;
	st->size = za->cdir->entry[index].uncomp_size;
	st->mtime = za->cdir->entry[index].last_mod;
	st->comp_size = za->cdir->entry[index].comp_size;
	st->comp_method = za->cdir->entry[index].comp_method;
	if (za->cdir->entry[index].bitflags & ZIP_GPBF_ENCRYPTED) {
	    if (za->cdir->entry[index].bitflags & ZIP_GPBF_STRONG_ENCRYPTION) {
		/* XXX */
		st->encryption_method = ZIP_EM_UNKNOWN;
	    }
	    else
		st->encryption_method = ZIP_EM_TRAD_PKWARE;
	}
	else
	    st->encryption_method = ZIP_EM_NONE;
	/* st->bitflags = za->cdir->entry[index].bitflags; */
    }

    st->index = index;
    st->name = name;
    
    return 0;
}
/*
  zip_stat_init.c -- initialize struct zip_stat.
  Copyright (C) 2006-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN void
zip_stat_init(struct zip_stat *st)
{
    st->name = NULL;
    st->index = -1;
    st->crc = 0;
    st->mtime = (time_t)-1;
    st->size = -1;
    st->comp_size = -1;
    st->comp_method = ZIP_CM_STORE;
    st->encryption_method = ZIP_EM_NONE;
}
/*
  zip_sterror.c -- get string representation of zip error
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include "zipint.h"



ZIP_EXTERN const char *
zip_strerror(struct zip *za)
{
    return _zip_error_strerror(&za->error);
}
/*
  zip_unchange.c -- undo changes to file in zip archive
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_unchange(struct zip *za, int idx)
{
    return _zip_unchange(za, idx, 0);
}



int
_zip_unchange(struct zip *za, int idx, int allow_duplicates)
{
    int i;
    
    if (idx < 0 || idx >= za->nentry) {
	_zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return -1;
    }

    if (za->entry[idx].ch_filename) {
	if (!allow_duplicates) {
	    i = _zip_name_locate(za,
			 _zip_get_name(za, idx, ZIP_FL_UNCHANGED, NULL),
				 0, NULL);
	    if (i != -1 && i != idx) {
		_zip_error_set(&za->error, ZIP_ER_EXISTS, 0);
		return -1;
	    }
	}

	free(za->entry[idx].ch_filename);
	za->entry[idx].ch_filename = NULL;
    }

    free(za->entry[idx].ch_comment);
    za->entry[idx].ch_comment = NULL;
    za->entry[idx].ch_comment_len = -1;

    _zip_unchange_data(za->entry+idx);

    return 0;
}
/*
  zip_unchange.c -- undo changes to all files in zip archive
  Copyright (C) 1999-2007 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_unchange_all(struct zip *za)
{
    int ret, i;

    ret = 0;
    for (i=0; i<za->nentry; i++)
	ret |= _zip_unchange(za, i, 1);

    ret |= zip_unchange_archive(za);

    return ret;
}
/*
  zip_unchange_archive.c -- undo global changes to ZIP archive
  Copyright (C) 2006-2008 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"



ZIP_EXTERN int
zip_unchange_archive(struct zip *za)
{
    free(za->ch_comment);
    za->ch_comment = NULL;
    za->ch_comment_len = -1;

    za->ch_flags = za->flags;

    return 0;
}
/*
  $NiH: zip_unchange_data.c,v 1.14 2004/11/30 23:02:47 wiz Exp $

  zip_unchange_data.c -- undo helper function
  Copyright (C) 1999, 2004 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#include <stdlib.h>

#include "zipint.h"

void
_zip_unchange_data(struct zip_entry *ze)
{
    if (ze->source) {
	(void)ze->source->f(ze->source->ud, NULL, 0, ZIP_SOURCE_FREE);
	free(ze->source);
	ze->source = NULL;
    }
    
    ze->state = ze->ch_filename ? ZIP_ST_RENAMED : ZIP_ST_UNCHANGED;
}

