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

#ifndef COMMONAPI_IMAGEINFO_H_
#define COMMONAPI_IMAGEINFO_H_

/** \file
 * \brief Mostly legacy API definitions and declaration.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Update status at last boot. */
enum {
	SBM_UPDATE_NONE, /**< No update took place. */
	SBM_UPDATE_SUCCESSFUL, /**< Update successful. */
	SBM_UPDATE_ERROR, /**< Update failed. */
	SBM_UPDATE_FAILED_VERSION, /**< Version rollback attempted. */
	SBM_UPDATE_FAILED_TARGET /**< Update incorrectly targeted. */
};

typedef struct
{
    uint16_t app_type;
    uint8_t installed;
    uint32_t start_addr;
    uint32_t end_addr;
    uint32_t app_version;       /** First byte is num bytes of version. */
} app_info_record;

#ifdef __cplusplus
}
#endif

#endif /* COMMONAPI_IMAGEINFO_H_ */
