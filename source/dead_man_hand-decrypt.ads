--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Ada.Streams;

with Util.Log.Loggers;

package Dead_Man_Hand.Decrypt is

   function Decode_Base64
     (Logger : Util.Log.Loggers.Logger;
      Text   : String) return Ada.Streams.Stream_Element_Array;

   procedure Decrypt_RSA
     (Logger   : Util.Log.Loggers.Logger;
      Key      : String;
      Text     : String);

   procedure Decrypt_ED25519
     (Logger   : Util.Log.Loggers.Logger;
      Key      : String;
      Text     : String);

end Dead_Man_Hand.Decrypt;