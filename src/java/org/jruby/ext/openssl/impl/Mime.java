/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
 * 
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.impl;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public interface Mime {
    Mime DEFAULT = new Mime() {
            private final static int MIME_INVALID = 0;
            private final static int MIME_START = 1;
            private final static int MIME_TYPE = 2;
            private final static int MIME_NAME = 3;
            private final static int MIME_VALUE = 4;
            private final static int MIME_QUOTE = 5;
            private final static int MIME_COMMENT = 6;

            private final static int MAX_SMLEN = 1024;

            public List<MimeHeader> parseHeaders(BIO bio) {
                int state = 0;
                byte[] linebuf = new byte[MAX_SMLEN];
                int len = 0;
                MimeHeader mhdr = null;

                List<MimeHeader> headers = new ArrayList<MimeHeader>();

//                 while((len = bio.gets(linebuf, MAX_SMLEN)) > 0) {
//                     if(mhdr != null && Character.isSpaceChar((char)linebuf[0])) {
//                         state = MIME_NAME;
//                     } else {
//                         state = MIME_START;
//                     }

//                 }


// 	char *p, *q, c;
// 	char *ntmp;
// 	char linebuf[MAX_SMLEN];
// 	MIME_HEADER *mhdr = NULL;
// 	STACK_OF(MIME_HEADER) *headers;
// 	int len, state, save_state = 0;

// 	headers = sk_MIME_HEADER_new(mime_hdr_cmp);
// 	while ((len = BIO_gets(bio, linebuf, MAX_SMLEN)) > 0) {
//         /* If whitespace at line start then continuation line */
//         if(mhdr && isspace((unsigned char)linebuf[0])) state = MIME_NAME;
//         else state = MIME_START;
//         ntmp = NULL;
//         /* Go through all characters */
//         for(p = linebuf, q = linebuf; (c = *p) && (c!='\r') && (c!='\n'); p++) {

//             /* State machine to handle MIME headers
//              * if this looks horrible that's because it *is*
//              */

//             switch(state) {
// 			case MIME_START:
//                 if(c == ':') {
//                     state = MIME_TYPE;
//                     *p = 0;
//                     ntmp = strip_ends(q);
//                     q = p + 1;
//                 }
//                 break;

// 			case MIME_TYPE:
//                 if(c == ';') {
//                     mime_debug("Found End Value\n");
//                     *p = 0;
//                     mhdr = mime_hdr_new(ntmp, strip_ends(q));
//                     sk_MIME_HEADER_push(headers, mhdr);
//                     ntmp = NULL;
//                     q = p + 1;
//                     state = MIME_NAME;
//                 } else if(c == '(') {
//                     save_state = state;
//                     state = MIME_COMMENT;
//                 }
//                 break;

// 			case MIME_COMMENT:
//                 if(c == ')') {
//                     state = save_state;
//                 }
//                 break;

// 			case MIME_NAME:
//                 if(c == '=') {
//                     state = MIME_VALUE;
//                     *p = 0;
//                     ntmp = strip_ends(q);
//                     q = p + 1;
//                 }
//                 break ;

// 			case MIME_VALUE:
//                 if(c == ';') {
//                     state = MIME_NAME;
//                     *p = 0;
//                     mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
//                     ntmp = NULL;
//                     q = p + 1;
//                 } else if (c == '"') {
//                     mime_debug("Found Quote\n");
//                     state = MIME_QUOTE;
//                 } else if(c == '(') {
//                     save_state = state;
//                     state = MIME_COMMENT;
//                 }
//                 break;

// 			case MIME_QUOTE:
//                 if(c == '"') {
//                     mime_debug("Found Match Quote\n");
//                     state = MIME_VALUE;
//                 }
//                 break;
//             }
//         }

//         if(state == MIME_TYPE) {
//             mhdr = mime_hdr_new(ntmp, strip_ends(q));
//             sk_MIME_HEADER_push(headers, mhdr);
//         } else if(state == MIME_VALUE)
//             mime_hdr_addparam(mhdr, ntmp, strip_ends(q));
//         if(p == linebuf) break;	/* Blank line means end of headers */
//     }

//     return headers;


                return null;
            }

            public MimeHeader findHeader(List<MimeHeader> headers, String key) {
                for(MimeHeader hdr : headers) {
                    if(hdr.getName().equals(key)) {
                        return hdr;
                    }
                }

                return null;
            }

            public MimeParam findParam(MimeHeader header, String key) {
                for(MimeParam par : header.getParams()) {
                    if(par.getParamName().equals(key)) {
                        return par;
                    }
                }

                return null;
            }
        };


    /* c: mime_parse_hdr
     *
     */
    List<MimeHeader> parseHeaders(BIO bio); 

    /* c: mime_hdr_find
     *
     */
    MimeHeader findHeader(List<MimeHeader> headers, String key); 

    /* c: mime_param_find
     *
     */
    MimeParam findParam(MimeHeader header, String key); 
}// Mime
