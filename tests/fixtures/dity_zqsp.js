// Test file for invisible character detection
// Contains various Unicode obfuscation techniques

// Zero-width space test
function normalLook​ing() {  // U+200B between 'normalLook' and 'ing'
    return "hidden";
}

// Zero-width joiner
let test‍Variable = 42;  // U+200D in variable name

// RTL Override - makes code appear reversed
let ‮evǝlyve_uoy = "malicious";  // U+202E before variable

// Word joiner
const password = "admin2060";​ // U+2060 after string

// Variation selectors
let emoji​ = "test";  // U+FE00 after emoji

// No-break space instead of regular space
let  x = 5;  // U+00A0 (no-break space) instead of regular space

// Figure space
let y = 10;  // U+2007 (figure space) in variable

// Narrow no-break space
let z = 15;  // U+202F (narrow no-break space)

// Line separator
let normal = "line1";  // U+2028 (line separator) after semicolon
let nextLine = "line2";

// Paragraph separator
let para1 = "text1";
// U+2029 (paragraph separator) before next line
let para2 = "text2";

// Soft hyphen
let secre­tKey = "classified";  // U+00AD (soft hyphen) in variable

// Hangul filler
let testㄴ = "invisible";  // U+3164 (Hangul filler) in variable

// Bidirectional embeddings
let user‪admin‬ = "root";  // U+202A LTR EMBEDDING and U+202B RTL EMBEDDING

// Pop directional formatting
let format‬ted = "data";  // U+202C POP DIRECTIONAL FORMATTING

// LTR/RTL marks
let text‮english = "code";  // U+200F (RTL mark)

// Bidi isolates
let iso⁦lated⁩ = "test";  // U+2066 LTR ISOLATE and U+2069 POP ISOLATE

// Arabic letter mark
let arabic‫ = "text";  // U+061C (Arabic Letter Mark)

// Left-to-right override
let override‬ = 99;  // U+202D LTR OVERRIDE

// Right-to-left override
let override‮ = 88;  // U+202E RTL OVERRIDE

// FIRST STRONG ISOLATE
let strong⁨test⁩ = "value";  // U+2068 and U+2069

// Normal comment
/* This block comment looks normal
   but has a zero-width non-joiner: ‌
   U+200C in the middle */

function legitimateCode() {
    console.log("This looks normal");
    return true;
}