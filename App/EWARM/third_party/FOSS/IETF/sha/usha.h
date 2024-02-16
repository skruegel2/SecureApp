/**************************** usha.c ***************************/
/***************** See RFC 6234 for details. *******************/
/* Copyright (c) 2011 IETF Trust and the persons identified as */
/* authors of the code.  All rights reserved.                  */
/* See sha.h for terms of use and redistribution.              */

/*
 *  Description:
 *     This file defines a unified interface to the SHA algorithms.
 */
#ifndef USHA_H
#define USHA_H

#include "sha.h"

/*
 *  USHAReset
 *
 *  Description:
 *      This function will initialize the SHA Context in preparation
 *      for computing a new SHA message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          Selects which SHA reset to call
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int USHAReset(USHAContext *context, enum SHAversion whichSha);

/*
 *  USHAInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update.
 *      message_array: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int USHAInput(USHAContext *context, const uint8_t *bytes, unsigned int bytecount);

/*
 * USHAFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int USHAFinalBits(USHAContext *context, uint8_t bits, unsigned int bit_count);

/*
 * USHAResult
 *
 * Description:
 *   This function will return the message digest of the appropriate
 *   bit size, as returned by USHAHashSizeBits(whichSHA) for the
 *   'whichSHA' value used in the preceding call to USHAReset,
 *   into the Message_Digest array provided by the caller.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA-1 hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int USHAResult(USHAContext *context, uint8_t Message_Digest[USHAMaxHashSize]);

/*
 * USHABlockSize
 *
 * Description:
 *   This function will return the blocksize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   block size
 *
 */
int USHABlockSize(enum SHAversion whichSha);

/*
 * USHAHashSize
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size
 *
 */
int USHAHashSize(enum SHAversion whichSha);

#endif /* USHA_H */

