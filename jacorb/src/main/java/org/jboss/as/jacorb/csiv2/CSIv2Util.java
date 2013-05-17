/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.as.jacorb.csiv2;

import java.io.UnsupportedEncodingException;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.jboss.as.jacorb.JacORBLogger;
import org.jboss.as.jacorb.JacORBMessages;
import org.jboss.as.jacorb.JacORBSubsystemConstants;
import org.jboss.as.jacorb.service.CorbaORBService;
import org.omg.CORBA.Any;
import org.omg.CORBA.BAD_PARAM;
import org.omg.CORBA.ORB;
import org.omg.CSI.ITTAnonymous;
import org.omg.CSI.ITTDistinguishedName;
import org.omg.CSI.ITTPrincipalName;
import org.omg.CSI.ITTX509CertChain;
import org.omg.CSIIOP.AS_ContextSec;
import org.omg.CSIIOP.CompoundSecMech;
import org.omg.CSIIOP.CompoundSecMechList;
import org.omg.CSIIOP.CompoundSecMechListHelper;
import org.omg.CSIIOP.Confidentiality;
import org.omg.CSIIOP.DetectMisordering;
import org.omg.CSIIOP.DetectReplay;
import org.omg.CSIIOP.EstablishTrustInClient;
import org.omg.CSIIOP.EstablishTrustInTarget;
import org.omg.CSIIOP.IdentityAssertion;
import org.omg.CSIIOP.Integrity;
import org.omg.CSIIOP.SAS_ContextSec;
import org.omg.CSIIOP.ServiceConfiguration;
import org.omg.CSIIOP.TAG_CSI_SEC_MECH_LIST;
import org.omg.CSIIOP.TAG_NULL_TAG;
import org.omg.CSIIOP.TAG_TLS_SEC_TRANS;
import org.omg.CSIIOP.TLS_SEC_TRANS;
import org.omg.CSIIOP.TLS_SEC_TRANSHelper;
import org.omg.CSIIOP.TransportAddress;
import org.omg.GSSUP.GSSUPMechOID;
import org.omg.GSSUP.InitialContextToken;
import org.omg.GSSUP.InitialContextTokenHelper;
import org.omg.IOP.Codec;
import org.omg.IOP.CodecPackage.InvalidTypeForEncoding;
import org.omg.IOP.TaggedComponent;
import org.omg.PortableInterceptor.ClientRequestInfo;
import org.omg.SSLIOP.SSL;
import org.omg.SSLIOP.SSLHelper;
import org.omg.SSLIOP.TAG_SSL_SEC_TRANS;

/**
 * <p>
 * This class defines utility methods for creating, comparing, encoding and decoding CSIv2 components.
 * </p>
 *
 * @author <a href="mailto:reverbel@ime.usp.br">Francisco Reverbel</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public final class CSIv2Util {

    /**
     * DER-encoded ASN.1 representation of the GSSUP mechanism OID.
     */
    private static final byte[] gssUpMechOidArray = createGSSUPMechOID();

    /**
     * <p>
     * Private constructor to implement the singleton pattern.
     * </p>
     */
    private CSIv2Util() {
    }

    /**
     * <p>
     * Make a deep copy of an {@code IOP:TaggedComponent}.
     * </p>
     *
     * @param tc the {@code TaggedComponent} to be copied.
     * @return a reference to the created copy.
     */
    public static TaggedComponent createCopy(TaggedComponent tc) {
        TaggedComponent copy = null;

        if (tc != null) {
            byte[] buf = new byte[tc.component_data.length];
            System.arraycopy(tc.component_data, 0, buf, 0, tc.component_data.length);
            copy = new TaggedComponent(tc.tag, buf);
        }
        return copy;
    }

    /**
     * <p>
     * Create a {@code TransportAddress[]} with a single {@code TransportAddress}.
     * </p>
     *
     * @param host a {@code String} representing the address host.
     * @param port an {@code int} representing the address port.
     * @return the constructed {@code TransportAddress} array.
     */
    public static TransportAddress[] createTransportAddress(String host, int port) {
        // idl type is unsigned sort, so we need this trick
        short short_port = (port > 32767) ? (short) (port - 65536) : (short) port;

        TransportAddress ta = new TransportAddress(host, short_port);
        TransportAddress[] taList = new TransportAddress[1];
        taList[0] = ta;

        return taList;
    }

    /**
     * <p>
     * Create an ASN.1, DER encoded representation for the GSSUP OID mechanism.
     * </p>
     *
     * @return the DER encoded representation of the GSSUP OID.
     */
    public static byte[] createGSSUPMechOID() {
        // kudos to org.ietf.jgss.Oid for the Oid utility need to strip the "oid:" part of the GSSUPMechOID first.

        byte[] retval = {};
        try {
            Oid oid = new Oid(GSSUPMechOID.value.substring(4));
            retval = oid.getDER();
        } catch (GSSException e) {
            JacORBLogger.ROOT_LOGGER.caughtExceptionEncodingGSSUPMechOID(e);
        }
        return retval;
    }

    /**
     * <p/>
     * Generate an exported name as specified in [RFC 2743], section 3.2 copied below:
     * <p/>
     * 3.2: Mechanism-Independent Exported Name Object Format
     * <p/>
     * This section specifies a mechanism-independent level of encapsulating representation for names exported via the
     * GSS_Export_name() call, including an object identifier representing the exporting mechanism. The format of names
     * encapsulated via this representation shall be defined within individual mechanism drafts.  The Object Identifier
     * value to indicate names of this type is defined in Section 4.7 of this document.
     * <p/>
     * No name type OID is included in this mechanism-independent level of format definition, since (depending on
     * individual mechanism specifications) the enclosed name may be implicitly typed or may be explicitly typed using
     * a means other than OID encoding.
     * <p/>
     * The bytes within MECH_OID_LEN and NAME_LEN elements are represented most significant byte first (equivalently,
     * in IP network byte order).
     * <p/>
     * Length          Name            Description
     * <p/>
     * 2               TOK_ID          Token Identifier
     * For exported name objects, this must be hex 04 01.
     * 2               MECH_OID_LEN    Length of the Mechanism OID
     * MECH_OID_LEN    MECH_OID        Mechanism OID, in DER
     * 4               NAME_LEN        Length of name
     * NAME_LEN        NAME            Exported name; format defined in applicable mechanism draft.
     * <p/>
     * A concrete example of the contents of an exported name object, derived from the Kerberos Version 5 mechanism, is
     * as follows:
     * <p/>
     * 04 01 00 0B 06 09 2A 86 48 86 F7 12 01 02 02 hx xx xx xl pp qq ... zz
     * <p/>
     * ...
     *
     * @param oid  the DER encoded OID.
     * @param name the name to be converted to {@code GSSExportedName}.
     * @return a {@code byte[]} representing the exported name.
     */
    public static byte[] createGSSExportedName(byte[] oid, byte[] name) {
        int olen = oid.length;
        int nlen = name.length;

        // size according to spec.
        int size = 2 + 2 + olen + 4 + nlen;

        // allocate space for the exported name.
        byte[] buf = new byte[size];
        // index.
        int i = 0;

        // standard header.
        buf[i++] = 0x04;
        buf[i++] = 0x01;

        // encode oid length.
        buf[i++] = (byte) (olen & 0xFF00);
        buf[i++] = (byte) (olen & 0x00FF);

        // copy the oid in the exported name buffer.
        System.arraycopy(oid, 0, buf, i, olen);
        i += olen;

        // encode the name length in the exported buffer.
        buf[i++] = (byte) (nlen & 0xFF000000);
        buf[i++] = (byte) (nlen & 0x00FF0000);
        buf[i++] = (byte) (nlen & 0x0000FF00);
        buf[i++] = (byte) (nlen & 0x000000FF);

        // finally, copy the name bytes.
        System.arraycopy(name, 0, buf, i, nlen);

        return buf;
    }

    /**
     * <p>
     * ASN.1-encode an {@code InitialContextToken} as defined in RFC 2743, Section 3.1, "Mechanism-Independent Token
     * Format", pp. 81-82. The encoded token contains the ASN.1 tag 0x60, followed by a token length (which is itself
     * stored in a variable-lenght format and takes 1 to 5 bytes), the GSSUP mechanism identifier, and a mechanism-specific
     * token, which in this case is a CDR encapsulation of the GSSUP {@code InitialContextToken} in the {@code authToken}
     * parameter.
     * </p>
     *
     * @param authToken the {@code InitialContextToken} to be encoded.
     * @param codec     the {@code Codec} used to encode the token.
     * @return a {@code byte[]} representing the encoded token.
     */
    public static byte[] encodeInitialContextToken(InitialContextToken authToken, Codec codec) {
        byte[] out;
        Any any = ORB.init().create_any();
        InitialContextTokenHelper.insert(any, authToken);
        try {
            out = codec.encode_value(any);
        } catch (Exception e) {
            return new byte[0];
        }

        int length = out.length + gssUpMechOidArray.length;
        int n;

        if (length < (1 << 7)) {
            n = 0;
        } else if (length < (1 << 8)) {
            n = 1;
        } else if (length < (1 << 16)) {
            n = 2;
        } else if (length < (1 << 24)) {
            n = 3;
        } else {// if (length < (1 << 32))
            n = 4;
        }

        byte[] encodedToken = new byte[2 + n + length];
        encodedToken[0] = 0x60;

        if (n == 0) {
            encodedToken[1] = (byte) length;
        } else {
            encodedToken[1] = (byte) (n | 0x80);
            switch (n) {
                case 1:
                    encodedToken[2] = (byte) length;
                    break;
                case 2:
                    encodedToken[2] = (byte) (length >> 8);
                    encodedToken[3] = (byte) length;
                    break;
                case 3:
                    encodedToken[2] = (byte) (length >> 16);
                    encodedToken[3] = (byte) (length >> 8);
                    encodedToken[4] = (byte) length;
                    break;
                default: // case 4:
                    encodedToken[2] = (byte) (length >> 24);
                    encodedToken[3] = (byte) (length >> 16);
                    encodedToken[4] = (byte) (length >> 8);
                    encodedToken[5] = (byte) length;
            }
        }
        System.arraycopy(gssUpMechOidArray, 0, encodedToken, 2 + n, gssUpMechOidArray.length);
        System.arraycopy(out, 0, encodedToken, 2 + n + gssUpMechOidArray.length, out.length);

        return encodedToken;
    }

    /**
     * <p>
     * Decodes an ASN.1-encoded {@code InitialContextToken}. See {@code encodeInitialContextToken} for a description of
     * the encoded token format.
     * </p>
     *
     * @param encodedToken the encoded token.
     * @param codec        the {@code Codec} used to decode the token.
     * @return the decoded {@code InitialContextToken} instance.
     * @see #encodeInitialContextToken(org.omg.GSSUP.InitialContextToken, org.omg.IOP.Codec)
     */
    public static InitialContextToken decodeInitialContextToken(byte[] encodedToken, Codec codec) {
        if (encodedToken[0] != 0x60)
            return null;

        int encodedLength = 0;
        int n = 0;

        if (encodedToken[1] >= 0)
            encodedLength = encodedToken[1];
        else {
            n = encodedToken[1] & 0x7F;
            for (int i = 1; i <= n; i++) {
                encodedLength += (encodedToken[1 + i] & 0xFF) << (n - i) * 8;
            }
        }

        int length = encodedLength - gssUpMechOidArray.length;
        byte[] encodedInitialContextToken = new byte[length];

        System.arraycopy(encodedToken, 2 + n + gssUpMechOidArray.length,
                encodedInitialContextToken, 0,
                length);
        Any any;
        try {
            any = codec.decode_value(encodedInitialContextToken, InitialContextTokenHelper.type());
        } catch (Exception e) {
            return null;
        }

        return InitialContextTokenHelper.extract(any);
    }

    /**
     * <p>
     * ASN.1-encodes a GSS exported name with the GSSUP mechanism OID. See {@code createGSSExportedName} for a
     * description of the encoding format.
     * </p>
     *
     * @param name the exported name to be encoded.
     * @return a {@code byte[]} representing the encoded exported name.
     * @see #createGSSExportedName(byte[], byte[])
     */
    public static byte[] encodeGssExportedName(byte[] name) {
        return createGSSExportedName(gssUpMechOidArray, name);
    }

    /**
     * <p>
     * Decodes a GSS exported name that has been encoded with the GSSUP mechanism OID. See {@code createGSSExportedName}
     * for a description of the encoding format.
     * </p>
     *
     * @param encodedName the encoded exported name.
     * @return a {@code byte[]} representing the decoded exported name.
     * @see #createGSSExportedName(byte[], byte[])
     */
    public static byte[] decodeGssExportedName(byte[] encodedName) {
        if (encodedName[0] != 0x04 || encodedName[1] != 0x01)
            return null;

        int mechOidLength = (encodedName[2] & 0xFF) << 8; //MECH_OID_LEN
        mechOidLength += (encodedName[3] & 0xFF);      // MECH_OID_LEN

        byte[] oidArray = new byte[mechOidLength];
        System.arraycopy(encodedName, 4, oidArray, 0, mechOidLength);

        for (int i = 0; i < mechOidLength; i++) {
            if (gssUpMechOidArray[i] != oidArray[i]) {
                return null;
            }
        }

        int offset = 4 + mechOidLength;
        int nameLength = (encodedName[offset] & 0xFF) << 24;
        nameLength += (encodedName[++offset] & 0xFF) << 16;
        nameLength += (encodedName[++offset] & 0xFF) << 8;
        nameLength += (encodedName[++offset] & 0xFF);

        byte[] name = new byte[nameLength];
        System.arraycopy(encodedName, ++offset, name, 0, nameLength);

        return name;
    }

    /**
     * <p>
     * Helper method to be called from a client request interceptor. The {@code ri} parameter refers to the current
     * request. This method returns the first {@code CompoundSecMech} found in the target IOR such that
     * <ul>
     * <li>all {@code CompoundSecMech} requirements are satisfied by the options in the {@code clientSupports}
     * parameter, and</li>
     * <li>every requirement in the {@code clientRequires} parameter is satisfied by the {@code CompoundSecMech}.
     * </li>
     * </ul>
     * The method returns null if the target IOR contains no {@code CompoundSecMech}s or if no matching
     * {@code CompoundSecMech} is found.
     * </p>
     * <p>
     * Since this method is intended to be called from a client request interceptor, it converts unexpected exceptions
     * into {@code MARSHAL} exceptions.
     * </p>
     *
     * @param ri             a reference to the current {@code ClientRequestInfo}.
     * @param codec          the {@code Codec} used to decode the CSIv2 components.
     * @param clientSupports the client supported transport options that must be satisfied by the {@code CompoundSecMech}.
     * @param clientRequires the client required transport options that must be satisfied by the {@code CompoundSecMech}.
     * @return the {@code CompoundSecMech} instance that satisfies all client options, or {@code null} if no such object
     *         can be found.
     */
    public static CompoundSecMech getMatchingSecurityMech(ClientRequestInfo ri, Codec codec, short clientSupports,
                                                          short clientRequires) {
        CompoundSecMechList csmList;
        try {
            TaggedComponent tc = ri.get_effective_component(TAG_CSI_SEC_MECH_LIST.value);

            Any any = codec.decode_value(tc.component_data, CompoundSecMechListHelper.type());
            csmList = CompoundSecMechListHelper.extract(any);

            // look for the first matching security mech.
            for (int i = 0; i < csmList.mechanism_list.length; i++) {
                CompoundSecMech securityMech = csmList.mechanism_list[i];
                AS_ContextSec authConfig = securityMech.as_context_mech;

                if ((EstablishTrustInTarget.value & (clientRequires ^ authConfig.target_supports)
                        & ~authConfig.target_supports) != 0) {
                    // client requires EstablishTrustInTarget, but target does not support it: skip this securityMech.
                    continue;
                }

                if ((EstablishTrustInClient.value & (authConfig.target_requires ^ clientSupports)
                        & ~clientSupports) != 0) {
                    // target requires EstablishTrustInClient, but client does not support it: skip this securityMech.
                    continue;
                }

                SAS_ContextSec identityConfig = securityMech.sas_context_mech;

                if ((IdentityAssertion.value & (identityConfig.target_requires ^ clientSupports)
                        & ~clientSupports) != 0) {
                    // target requires IdentityAssertion, but client does not support it: skip this securityMech
                    continue;
                }

                // found matching securityMech.
                return securityMech;
            }
            // no matching securityMech was found.
            return null;
        } catch (BAD_PARAM e) {
            // no component with TAG_CSI_SEC_MECH_LIST was found.
            return null;
        } catch (org.omg.IOP.CodecPackage.TypeMismatch e) {
            // unexpected exception in codec
            throw JacORBMessages.MESSAGES.unexpectedException(e);
        } catch (org.omg.IOP.CodecPackage.FormatMismatch e) {
            // unexpected exception in codec
            throw JacORBMessages.MESSAGES.unexpectedException(e);
        }
    }

    /**
     * <p>
     * Generate a string representation of the {@code CompoundSecMech}.
     * </p>
     *
     * @param securityMech the {@code CompoundSecMech} to create the string for.
     * @param builder      the buffer to write to.
     */
    public static void toString(CompoundSecMech securityMech, StringBuilder builder) {
        AS_ContextSec asMech = securityMech != null ? securityMech.as_context_mech : null;
        SAS_ContextSec sasMech = securityMech != null ? securityMech.sas_context_mech : null;
        if (securityMech != null) {
            builder.append("CompoundSecMech[");
            builder.append("target_requires: ");
            builder.append(securityMech.target_requires);
            if (asMech != null) {
                builder.append("AS_ContextSec[");

                builder.append("client_authentication_mech: ");
                try {
                    builder.append(new String(asMech.client_authentication_mech, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    builder.append(e.getMessage());
                }
                builder.append(", target_name: ");
                try {
                    builder.append(new String(asMech.target_name, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    builder.append(e.getMessage());
                }
                builder.append(", target_requires: ");
                builder.append(asMech.target_requires);
                builder.append(", target_supports: ");
                builder.append(asMech.target_supports);
                builder.append("]");
            }
            if (sasMech != null) {
                builder.append("SAS_ContextSec[");
                builder.append("supported_identity_types: ");
                builder.append(sasMech.supported_identity_types);
                builder.append(", target_requires: ");
                builder.append(sasMech.target_requires);
                builder.append(", target_supports: ");
                builder.append(sasMech.target_supports);
                builder.append("]");
            }
            builder.append("]");
        }
    }
}
