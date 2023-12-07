       // these variables will be filled when generating the file - the template format is 'variable_name'
       const staticryptInitiator = 
       ((function(){
const exports = {};
const cryptoEngine = ((function(){
const exports = {};
const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
* Translates between utf8 encoded hexadecimal strings
* and Uint8Array bytes.
*/
const HexEncoder = {
/**
* hex string -> bytes
* @param {string} hexString
* @returns {Uint8Array}
*/
parse: function (hexString) {
   if (hexString.length % 2 !== 0) throw "Invalid hexString";
   const arrayBuffer = new Uint8Array(hexString.length / 2);

   for (let i = 0; i < hexString.length; i += 2) {
       const byteValue = parseInt(hexString.substring(i, i + 2), 16);
       if (isNaN(byteValue)) {
           throw "Invalid hexString";
       }
       arrayBuffer[i / 2] = byteValue;
   }
   return arrayBuffer;
},

/**
* bytes -> hex string
* @param {Uint8Array} bytes
* @returns {string}
*/
stringify: function (bytes) {
   const hexBytes = [];

   for (let i = 0; i < bytes.length; ++i) {
       let byteString = bytes[i].toString(16);
       if (byteString.length < 2) {
           byteString = "0" + byteString;
       }
       hexBytes.push(byteString);
   }
   return hexBytes.join("");
},
};

/**
* Translates between utf8 strings and Uint8Array bytes.
*/
const UTF8Encoder = {
parse: function (str) {
   return new TextEncoder().encode(str);
},

stringify: function (bytes) {
   return new TextDecoder().decode(bytes);
},
};

/**
* Salt and encrypt a msg with a password.
*/
async function encrypt(msg, hashedPassword) {
// Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

const encrypted = await subtle.encrypt(
   {
       name: ENCRYPTION_ALGO,
       iv: iv,
   },
   key,
   UTF8Encoder.parse(msg)
);

// iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
* Decrypt a salted msg using a password.
*
* @param {string} encryptedMsg
* @param {string} hashedPassword
* @returns {Promise<string>}
*/
async function decrypt(encryptedMsg, hashedPassword) {
const ivLength = IV_BITS / HEX_BITS;
const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
const encrypted = encryptedMsg.substring(ivLength);

const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

const outBuffer = await subtle.decrypt(
   {
       name: ENCRYPTION_ALGO,
       iv: iv,
   },
   key,
   HexEncoder.parse(encrypted)
);

return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
* Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
*
* @param {string} password
* @param {string} salt
* @returns {Promise<string>}
*/
async function hashPassword(password, salt) {
// we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
// iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
let hashedPassword = await hashLegacyRound(password, salt);

hashedPassword = await hashSecondRound(hashedPassword, salt);

return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
* This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
* compatibility.
*
* @param {string} password
* @param {string} salt
* @returns {Promise<string>}
*/
function hashLegacyRound(password, salt) {
return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
* Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
* remember-me/autodecrypt links, we need to support going from that to more iterations.
*
* @param hashedPassword
* @param salt
* @returns {Promise<string>}
*/
function hashSecondRound(hashedPassword, salt) {
return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
* Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
* backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
*
* @param hashedPassword
* @param salt
* @returns {Promise<string>}
*/
function hashThirdRound(hashedPassword, salt) {
return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
* Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
*
* @param {string} password
* @param {string} salt
* @param {int} iterations
* @param {string} hashAlgorithm
* @returns {Promise<string>}
*/
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

const keyBytes = await subtle.deriveBits(
   {
       name: "PBKDF2",
       hash: hashAlgorithm,
       iterations,
       salt: UTF8Encoder.parse(salt),
   },
   key,
   256
);

return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
const key = await subtle.importKey(
   "raw",
   HexEncoder.parse(hashedPassword),
   {
       name: "HMAC",
       hash: "SHA-256",
   },
   false,
   ["sign"]
);
const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

let byteArray;
let parsedInt;

// Keep generating new random bytes until we get a value that falls
// within a range that can be evenly divided by possibleCharacters.length
do {
   byteArray = crypto.getRandomValues(new Uint8Array(1));
   // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
   parsedInt = byteArray[0] & 0xff;
} while (parsedInt >= 256 - (256 % possibleCharacters.length));

// Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
const randomIndex = parsedInt % possibleCharacters.length;

return possibleCharacters[randomIndex];
}

/**
* Generate a random string of a given length.
*
* @param {int} length
* @returns {string}
*/
function generateRandomString(length) {
let randomString = "";

for (let i = 0; i < length; i++) {
   randomString += getRandomAlphanum();
}

return randomString;
}
exports.generateRandomString = generateRandomString;

return exports;
})());
const codec = ((function(){
const exports = {};
/**
* Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
*
* @param cryptoEngine - the engine to use for encryption / decryption
*/
function init(cryptoEngine) {
const exports = {};

/**
* Top-level function for encoding a message.
* Includes password hashing, encryption, and signing.
*
* @param {string} msg
* @param {string} password
* @param {string} salt
*
* @returns {string} The encoded text
*/
async function encode(msg, password, salt) {
   const hashedPassword = await cryptoEngine.hashPassword(password, salt);

   const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

   // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
   // it in localStorage safely, we don't use the clear text password)
   const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

   return hmac + encrypted;
}
exports.encode = encode;

/**
* Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
* we don't need to hash the password multiple times.
*
* @param {string} msg
* @param {string} hashedPassword
*
* @returns {string} The encoded text
*/
async function encodeWithHashedPassword(msg, hashedPassword) {
   const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

   // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
   // it in localStorage safely, we don't use the clear text password)
   const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

   return hmac + encrypted;
}
exports.encodeWithHashedPassword = encodeWithHashedPassword;

/**
* Top-level function for decoding a message.
* Includes signature check and decryption.
*
* @param {string} signedMsg
* @param {string} hashedPassword
* @param {string} salt
* @param {int} backwardCompatibleAttempt
* @param {string} originalPassword
*
* @returns {Object} {success: true, decoded: string} | {success: false, message: string}
*/
async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
   const encryptedHMAC = signedMsg.substring(0, 64);
   const encryptedMsg = signedMsg.substring(64);
   const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

   if (decryptedHMAC !== encryptedHMAC) {
       // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
       // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
       originalPassword = originalPassword || hashedPassword;
       if (backwardCompatibleAttempt === 0) {
           const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

           return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
       }
       if (backwardCompatibleAttempt === 1) {
           let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
           updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

           return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
       }

       return { success: false, message: "Signature mismatch" };
   }

   return {
       success: true,
       decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
   };
}
exports.decode = decode;

return exports;
}
exports.init = init;

return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
* Initialize the staticrypt module, that exposes functions callbable by the password_template.
*
* @param {{
*  staticryptEncryptedMsgUniqueVariableName: string,
*  isRememberEnabled: boolean,
*  rememberDurationInDays: number,
*  staticryptSaltUniqueVariableName: string,
* }} staticryptConfig - object of data that is stored on the password_template at encryption time.
*
* @param {{
*  rememberExpirationKey: string,
*  rememberPassphraseKey: string,
*  replaceHtmlCallback: function,
*  clearLocalStorageCallback: function,
* }} templateConfig - object of data that can be configured by a custom password_template.
*/
function init(staticryptConfig, templateConfig) {
const exports = {};

/**
* Decrypt our encrypted page, replace the whole HTML.
*
* @param {string} hashedPassword
* @returns {Promise<boolean>}
*/
async function decryptAndReplaceHtml(hashedPassword) {
   const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
   const { replaceHtmlCallback } = templateConfig;

   const result = await decode(
       staticryptEncryptedMsgUniqueVariableName,
       hashedPassword,
       staticryptSaltUniqueVariableName
   );
   if (!result.success) {
       return false;
   }
   const plainHTML = result.decoded;

   // if the user configured a callback call it, otherwise just replace the whole HTML
   if (typeof replaceHtmlCallback === "function") {
       replaceHtmlCallback(plainHTML);
   } else {
       document.write(plainHTML);
       document.close();
   }

   return true;
}

/**
* Attempt to decrypt the page and replace the whole HTML.
*
* @param {string} password
* @param {boolean} isRememberChecked
*
* @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
*   expose more information in the future we can do it without breaking the password_template
*/
async function handleDecryptionOfPage(password, isRememberChecked) {
   const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
   const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

   // decrypt and replace the whole page
   const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

   const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

   if (!isDecryptionSuccessful) {
       return {
           isSuccessful: false,
           hashedPassword,
       };
   }

   // remember the hashedPassword and set its expiration if necessary
   if (isRememberEnabled && isRememberChecked) {
       window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

       // set the expiration if the duration isn't 0 (meaning no expiration)
       if (rememberDurationInDays > 0) {
           window.localStorage.setItem(
               rememberExpirationKey,
               (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
           );
       }
   }

   return {
       isSuccessful: true,
       hashedPassword,
   };
}
exports.handleDecryptionOfPage = handleDecryptionOfPage;

/**
* Clear localstorage from staticrypt related values
*/
function clearLocalStorage() {
   const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

   if (typeof clearLocalStorageCallback === "function") {
       clearLocalStorageCallback();
   } else {
       localStorage.removeItem(rememberPassphraseKey);
       localStorage.removeItem(rememberExpirationKey);
   }
}

async function handleDecryptOnLoad() {
   let isSuccessful = await decryptOnLoadFromUrl();

   if (!isSuccessful) {
       isSuccessful = await decryptOnLoadFromRememberMe();
   }

   return { isSuccessful };
}
exports.handleDecryptOnLoad = handleDecryptOnLoad;

/**
* Clear storage if we are logging out
*
* @returns {boolean} - whether we logged out
*/
function logoutIfNeeded() {
   const logoutKey = "staticrypt_logout";

   // handle logout through query param
   const queryParams = new URLSearchParams(window.location.search);
   if (queryParams.has(logoutKey)) {
       clearLocalStorage();
       return true;
   }

   // handle logout through URL fragment
   const hash = window.location.hash.substring(1);
   if (hash.includes(logoutKey)) {
       clearLocalStorage();
       return true;
   }

   return false;
}

/**
* To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
* try to do it if needed.
*
* @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
*/
async function decryptOnLoadFromRememberMe() {
   const { rememberDurationInDays } = staticryptConfig;
   const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

   // if we are login out, terminate
   if (logoutIfNeeded()) {
       return false;
   }

   // if there is expiration configured, check if we're not beyond the expiration
   if (rememberDurationInDays && rememberDurationInDays > 0) {
       const expiration = localStorage.getItem(rememberExpirationKey),
           isExpired = expiration && new Date().getTime() > parseInt(expiration);

       if (isExpired) {
           clearLocalStorage();
           return false;
       }
   }

   const hashedPassword = localStorage.getItem(rememberPassphraseKey);

   if (hashedPassword) {
       // try to decrypt
       const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

       // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
       // the user fill the password form again
       if (!isDecryptionSuccessful) {
           clearLocalStorage();
           return false;
       }

       return true;
   }

   return false;
}

function decryptOnLoadFromUrl() {
   const passwordKey = "staticrypt_pwd";

   // get the password from the query param
   const queryParams = new URLSearchParams(window.location.search);
   const hashedPasswordQuery = queryParams.get(passwordKey);

   // get the password from the url fragment
   const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
   const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

   const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

   if (hashedPassword) {
       return decryptAndReplaceHtml(hashedPassword);
   }

   return false;
}

return exports;
}
exports.init = init;

return exports;
})());
   ;
       const templateError = "template_error",
           isRememberEnabled = false,
           staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"b4bca2202532b2366e1a4ca482b986affc4a8505af8897be0572c7b2a4e250e35448929868f5359a7d1b267cc5dfe8e7a593d2a7f0aa101734b6f0dc163b508419a8f9b620c725bfbddd1a05637f18fb4455c84efb3fc19f1917964c5b1842cc0780755c7148392b11e1641329c34a69b12bf7ff744d3e6540acb84a02ca8725a8b4f130794be497cb6db380d0723e8aac32624075fb1454d4423aa4a77f84f4dc3a6d20a4055de6a7ff8411c2713c69edc0ad4626462d5ff295bfb53264756032f8866de35c43182b72bdbe3ddcfeab0cedb1618d17f7beb81ffeb0837e560f61944299d6abe3ab10c1584b7b2d861aafb2b948222a8ed6a947b6c7f15bc9130d809411c373720fe987971412b0caff","isRememberEnabled":false,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"b0033e6608aadd727c0a280015260fec"};

       // you can edit these values to customize some of the behavior of StatiCrypt
       const templateConfig = {
           rememberExpirationKey: "staticrypt_expiration",
           rememberPassphraseKey: "staticrypt_passphrase",
           replaceHtmlCallback: null,
           clearLocalStorageCallback: null,
       };

       // init the staticrypt engine
       const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

       // try to automatically decrypt on load if there is a saved password
       window.onload = async function () {
           const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

           // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
           // replaced, no need to do anything
           if (!isSuccessful) {
               // hide loading screen
               document.getElementById("staticrypt_loading").classList.add("hidden");
               document.getElementById("staticrypt_content").classList.remove("hidden");
               document.getElementById("staticrypt-password").focus();

               // show the remember me checkbox
               if (isRememberEnabled) {
                   document.getElementById("staticrypt-remember-label").classList.remove("hidden");
               }
           }
       };

       // handle password form submission
       document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
           e.preventDefault();

           const password = document.getElementById("staticrypt-password").value,
               isRememberChecked = document.getElementById("staticrypt-remember").checked;

           const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

           if (!isSuccessful) {
               alert(templateError);
           }
       });