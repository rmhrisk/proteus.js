/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

describe('IdentityKeyPair', function() {
  return it('serialises and deserialises', function() {
    var ikp, ikp_bytes, ikp_deser;
    ikp = Proteus.keys.IdentityKeyPair["new"]();
    ikp_bytes = ikp.serialise();
    ikp_deser = Proteus.keys.IdentityKeyPair.deserialise(ikp_bytes);
    assert(ikp.public_key.fingerprint() === ikp_deser.public_key.fingerprint());
    return assert(sodium.to_hex(new Uint8Array(ikp_bytes)) === sodium.to_hex(new Uint8Array(ikp_deser.serialise())));
  });
});
