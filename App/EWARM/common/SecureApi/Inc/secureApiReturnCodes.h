/********************************************************************************
* Copyright 2017-2022 Secure Thingz Ltd.
* All rights reserved.
*
* This source file and its use is subject to a Secure Thingz Embedded Trust
* License agreement. This source file may contain licensed source code from
* other third-parties and is subject to those license agreements as well.
*
* Permission to use, copy, modify, compile and distribute compiled binary of the
* source code for use as specified in the Embedded Trust license agreement is
* hereby granted provided that the this copyright notice and other third-party
* copyright notices appear in all copies of the source code.
*
* Distribution of Embedded Trust source code in any form is governed by the
* Embedded Trust license agreement. Use of the Secure Thingz name or trademark
* in any form is prohibited.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef SECURITY_API_RETURN_CODES_H
#define SECURITY_API_RETURN_CODES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Secure API error codes, these are all negative values. Any non-negative
 *        value is a success.
 *
 *        DO NOT RE-PURPOSE ANY CODES, each value must only ever be used for
 *        one purpose.
 *
 *        DO NOT SET ANY NON-NEGATIVE VALUES HERE.
 */
typedef enum
{
    SECURE_API_ERR_API_FAILURE = -1, /**< API failure */
    SECURE_API_ERR_COMMAND_FAILED = -2, /**< The processing of the API failed, a generic code to indicate failure */
    SECURE_API_ERR_BUFFER_LOCATION_INVALID = -3, /**< The location of the buffer provided is invalid */
    SECURE_API_ERR_BUFFER_SIZE_INVALID = -4, /**< The size of the buffer provided is invalid */
    /* Formerly SECURE_API_ERR_NO_PROVISIONED_DATA = -5	*/
    SECURE_API_ERR_SLOT_OUT_OF_RANGE = -6, /**< Requested slot index out of range */
    SECURE_API_ERR_SLOT_TYPE_MISMATCH = -7, /**< Looking in a slot of the wrong type */
    SECURE_API_ERR_NO_MATCHING_SLOT_FOUND = -8 /**< No slot matches the search criteria */
    /* Add more error codes here... */
} secure_api_error_codes_t;

/**
 * \brief Check that the secure API call has not returned an error.
 *
 * \param return The return value from a secure API call
 */
#define SECURE_API_CHECK_SUCCESS(return) ((return) >= 0)

/**
 * \brief Check that the secure API call has returned an error.
 *
 * \param return The return value from a secure API call
 */
#define SECURE_API_CHECK_FAIL(return) ((return) < 0)

/**
 * \brief Return a non-negative value so signal success
 */
#define SECURE_API_RETURN_SUCCESS 0

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_API_RETURN_CODES_H */
