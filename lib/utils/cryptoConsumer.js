/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, the contents of this file are
 * subject to the TOZNY NON-COMMERCIAL LICENSE (the "License") which
 * permits use of the software only by government agencies, schools,
 * universities, non-profit organizations or individuals on projects that
 * do not receive external funding other than government research grants
 * and contracts.  Any other use requires a commercial license. You may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at https://tozny.com/legal/non-commercial-license.
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations under
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2018-19.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2018-19 Tozny, LLC (https://tozny.com)
 */

'use strict'

export default class CryptoConsumer {
  /**
   * Abstract crypto instance which must be made concrete by the final implementing code.
   *
   * When creating an object with a concrete crypto instance, extend the and overload this getter to offer up a
   * valid, concrete implementation of the Crypto interface. No other overloading is necessary to make crypto available.
   *
   * example:
   *
   * ```
   * const myCrypto = new ConcreteCrypto()
   * Class MyClient extends Client {
   *   static get crypto() {
   *     return myCrypto
   *   }
   * }
   * ```
   *
   * IMPORTANT:
   * Static methods can use `this.crypto` to reference the concrete crypto methods in implementing classes. When a
   * static method is called, this is bound to the class constructor, which will be the implementing class. It
   * is odd to see `this` in static methods, however `this` is what allows for late static biding. In other words,
   * the static methods defined interface classes can fetch and use concrete crypto instance methods, which are
   * provided by the implementing child class. This is possible referencing `this` instead of referencing the interface
   * class directly.
   *
   * An additional instance level getter is also provided which allows fetching a child class's concrete crypto instance
   * in both static _and_ instance method contexts as `this.crypto`.
   *
   * @returns {Crypto} A Crypto instance allowing crypto operations in the Client methods.
   */
  static get crypto() {
    throw new Error(
      'The Client class must be extended with the get crypto method overloaded to provide a valid crypto instance.'
    )
  }

  /**
   * Gets the static crypto object so it can be accessed via `this.crypto` in instance methods.
   *
   * @returns {Crypto} The crypto object available in the implementing class
   */
  get crypto() {
    // Use this.constructor to ensure we referencing the implementing class, not an interface class.
    return this.constructor.crypto
  }
}
