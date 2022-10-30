/**
 * @file tls_octads.h
 * @author Mike Scott
 * @brief octad handling routines - octads don't overflow, they truncate
 *
 */ 

#ifndef TLS_OCTADS_H
#define TLS_OCTADS_H

// An octad - "a group or set of eight" - Oxford dictionary

//#define TLS_ARDUINO            /**< Define for Arduino-based implementation */

#include <stddef.h>

/**	@brief read milliseconds from a stop-watch 
 *
	@return milliseconds read from stop-watch
 */
#ifndef TLS_ARDUINO
extern unsigned long millis();
#endif
/**
	@brief Safe representation of an octad
*/
typedef struct
{
    int len;   /**< length in bytes  */
    int max;   /**< max length allowed - enforce truncation */
    char *val; /**< byte array  */
} octad;

/**	@brief Join len bytes of integer x to end of octad O (big endian)
 *
 	@param O octad to be appended to
	@param x integer to be appended to O
	@param len number of bytes in m

 */
extern void OCT_append_int(octad *O, unsigned int x, int len);

/**	@brief Join one octad to the end of another
 *
	@param O octad to be appended to
	@param P octad to be joined to the end of O
 */
extern void OCT_append_octad(octad *O, octad *P);

/**	@brief Compare two octads
 *
	@param O first octad to be compared
	@param P second octad to be compared
	@return true if equal, else false
 */
extern bool OCT_compare(octad *O, octad *P);

/**	@brief Shifts octad left by n bytes
 *
	Leftmost bytes disappear
 	@param O octad to be shifted
	@param n number of bytes to shift

 */
extern void OCT_shift_left(octad *O, int n);

/**	@brief Wipe clean an octad
 *
	@param O octad to be cleared
 */
extern void OCT_kill(octad *O);

/**	@brief Convert a hex number to an octad
 *
	@param O octad
	@param src Hex string to be converted
 */
extern void OCT_from_hex(octad *O, char *src);

/**	@brief Join from a C string to end of an octad
 *
	@param O octad to be written to
	@param s zero terminated string to be joined to octad
 */
extern void OCT_append_string(octad *O, char *s);

/**	@brief Join single byte to end of an octad, repeated n times
 *
	@param O octad to be written to
	@param b byte to be joined to end of octad
	@param n number of times b is to be joined
 */
extern void OCT_append_byte(octad *O, int b, int n);

/**	@brief Join bytes to end of an octad
 *
	@param O octad to be written to
	@param s byte array to be joined to end of octad
	@param n number of bytes to join
 */
extern void OCT_append_bytes(octad *O, char *s, int n);

/**	@brief Create an octad from a base64 number
 *
 	@param O octad to be populated
	@param b zero terminated base64 string

 */
extern void OCT_from_base64(octad *O, char *b);

/**	@brief Reverse bytes in an octad
 *
	@param O octad to be reversed
 */
extern void OCT_reverse(octad *O);

/**	@brief Reverse bytes in an octad
 *
	@param O octad to be truncated
    @param n the new shorter length
 */
extern void OCT_truncate(octad *O,int n);

/**	@brief Copy one octad into another
 *
 	@param O octad to be copied to
	@param P octad to be copied from

 */
extern void OCT_copy(octad *O, octad *P);

/**	@brief Output octad as hex string
 *
 	@param O octad to be output
    @param max the maximum output length
	@param s the char array to receive output

 */
extern bool OCT_output_hex(octad *O,int max,char *s);

/**	@brief Output octad as C ascii string
 *
 	@param O octad to be output
    @param max the maximum output length
	@param s the char array to receive output

 */
extern bool OCT_output_string(octad *O,int max,char *s);

/**	@brief Output octad as base64 string
 *
 	@param O octad to be output
    @param max the maximum output length
	@param s the char array to receive output

 */
extern void OCT_output_base64(octad *O,int max,char *s);
#endif
