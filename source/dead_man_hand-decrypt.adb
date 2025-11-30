--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Ada.Characters.Latin_1;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Directories;

with GNAT.SHA512;

with Util.Encoders;
with Util.Files;
with Util.Processes;
with Util.Streams.Pipes;

package body Dead_Man_Hand.Decrypt is

   subtype Stream_Element_Array_32 is
     Ada.Streams.Stream_Element_Array (1 .. 32);

   procedure Read_ED25519_Key
     (Logger  : Util.Log.Loggers.Logger;
      Key     : String;
      Value   : out Stream_Element_Array_32;
      Success : out Boolean);

   procedure ED25519_To_X25519 (Key : in out Stream_Element_Array_32);

   procedure Write_X25519_Key
     (Name : String;
      Key  : Stream_Element_Array_32);

   -------------------
   -- Decode_Base64 --
   -------------------

   function Decode_Base64
     (Logger : Util.Log.Loggers.Logger;
      Text   : String) return Ada.Streams.Stream_Element_Array
   is
      Decoder : constant Util.Encoders.Decoder :=
        Util.Encoders.Create ("base64");
      Fixed : String := Text;
      Last  : Natural := 0;
   begin
      for Char of Text loop
         if Char /= Ada.Characters.Latin_1.LF then
            Last := Last + 1;
            Fixed (Last) := Char;
         end if;
      end loop;

      return Result : constant Ada.Streams.Stream_Element_Array :=
         Decoder.Decode_Binary (Fixed (1 .. Last))
      do
         Logger.Info
           ("Decoding base64 into {0} bytes",
            Ada.Streams.Stream_Element_Offset'Image (Result'Length));
      end return;
   end Decode_Base64;

   ---------------------
   -- Decrypt_ED25519 --
   ---------------------

   procedure Decrypt_ED25519
     (Logger   : Util.Log.Loggers.Logger;
      Key      : String;
      Text     : String)
   is
      Private_Key : Stream_Element_Array_32;
      Success     : Boolean;

      procedure Remove_Password;

      ---------------------
      -- Remove_Password --
      ---------------------

      procedure Remove_Password is
         Pipe  : aliased Util.Streams.Pipes.Pipe_Stream;
      begin
         Ada.Directories.Copy_File
           (Source_Name => Key,
            Target_Name => "temp");

         Ada.Text_IO.Put_Line ("Starting 'ssh-keygen -p'");
         Ada.Text_IO.Put_Line ("It should ask for your private key password!");

         Pipe.Open
           (Command => "ssh-keygen -p -f temp -N ''",
            Mode => Util.Processes.READ);

         Logger.Info
           ("Command exited with status {0}",
            Integer'Image (Pipe.Get_Exit_Status));

         if Pipe.Get_Exit_Status = 0 then
            Logger.Info ("Decryption with 'ssh-keygen -p' successful!");
            Read_ED25519_Key (Logger, "temp", Private_Key, Success);
            Ada.Directories.Delete_File ("temp");
         else
            Logger.Info ("Decryption with 'ssh-keygen -p' failed!");
         end if;
      end Remove_Password;

   begin
      if not Ada.Directories.Exists (Key) then
         Ada.Text_IO.Put_Line
           ("Can't find private key file " & Key & " does not exist!");

         return;
      end if;

      Read_ED25519_Key (Logger, Key, Private_Key, Success);

      if not Success then
         Remove_Password;
      end if;

      if not Success then
         return;
      end if;

      ED25519_To_X25519 (Private_Key);
   end Decrypt_ED25519;

   -----------------
   -- Decrypt_RSA --
   -----------------

   procedure Decrypt_RSA
     (Logger   : Util.Log.Loggers.Logger;
      Key      : String;
      Text     : String)
   is
      --  Last  : Ada.Streams.Stream_Element_Offset;
      Pipe  : aliased Util.Streams.Pipes.Pipe_Stream;
      Bytes : constant Ada.Streams.Stream_Element_Array :=
        Decode_Base64 (Logger, Text);
   begin
      if not Ada.Directories.Exists (Key) then
         Ada.Text_IO.Put_Line
           ("Can't find private key file " & Key & " does not exist!");

         return;
      end if;

      Ada.Text_IO.Put_Line ("Starting 'openssl pkeyutl -decrypt'");
      Ada.Text_IO.Put_Line ("It may ask for your private key passphrase!");

      Pipe.Open
        (Command =>
          "openssl pkeyutl -decrypt -inkey """ &
           Key &
           """ -out result-rsa.txt",
         Mode => Util.Processes.WRITE);
      Pipe.Write (Bytes);
      Pipe.Flush;
      Pipe.Close;

      Logger.Info
        ("Command exited with status {0}",
         Integer'Image (Pipe.Get_Exit_Status));

      if Pipe.Get_Exit_Status = 0 then
         Logger.Info ("Decryption successful! See 'result-rsa.txt'");
      else
         Logger.Info ("Decryption failed!");
      end if;
   end Decrypt_RSA;

   -----------------------
   -- ED25519_To_X25519 --
   -----------------------

   procedure ED25519_To_X25519 (Key : in out Stream_Element_Array_32) is
      use type Ada.Streams.Stream_Element;
   begin
      --  Hash the key with SHA-512
      Key := GNAT.SHA512.Digest (Key);
      --  Clamp the key
      Key (1) := Key (1) and 16#F8#;
      Key (32) := (Key (32) and 16#7F#) or 16#40#;
   end ED25519_To_X25519;

   ----------------------
   -- Read_ED25519_Key --
   ----------------------

   procedure Read_ED25519_Key
     (Logger  : Util.Log.Loggers.Logger;
      Key     : String;
      Value   : out Stream_Element_Array_32;
      Success : out Boolean)
   is

      Text : Ada.Strings.Unbounded.Unbounded_String;

      procedure Each_line (Line : String);

      procedure Each_line (Line : String) is
      begin
         if Line'Length > 0 and then Line (Line'First) /= '-' then
            Ada.Strings.Unbounded.Append (Text, Line);
         end if;
      end Each_line;

      Decoder : constant Util.Encoders.Decoder :=
        Util.Encoders.Create ("base64");
   begin
      Util.Files.Read_File (Key, Each_line'Access);

      Logger.Info
        ("Read {0} base64 bytes from ED25519 key file {1}",
         Ada.Strings.Unbounded.Length (Text)'Image,
         Key);

      declare
         use type Ada.Streams.Stream_Element_Array;

         Nul : constant Character := Ada.Characters.Latin_1.NUL;

         Bytes : constant Ada.Streams.Stream_Element_Array :=
           Decoder.Decode_Binary
             (Ada.Strings.Unbounded.To_String (Text));

         Text : String (1 .. Bytes'Length)
           with Import, Address => Bytes'Address;
      begin
         Logger.Info
           ("Decoded ED25519 key into {0} bytes",
            Ada.Streams.Stream_Element_Offset'Image (Bytes'Length));

         if Text (1 .. 15) /= "openssh-key-v1" & Nul
           or else Bytes (16 .. 19) /= (0, 0, 0, 4)
           or else Text (20 .. 23) /= "none"
           or else Bytes (24 .. 27) /= (0, 0, 0, 4)
           or else Text (28 .. 31) /= "none"
           or else Bytes (32 .. 35) /= (0, 0, 0, 0)
           or else Bytes (36 .. 39) /= (0, 0, 0, 1)  --  number of keys
           or else Bytes (40 .. 43) /= (0, 0, 0, 51)  --  key length
           or else Bytes (44 .. 47) /= (0, 0, 0, 11)  --  key type length
           or else Text (48 .. 58) /= "ssh-ed25519"
           or else Bytes (59 .. 62) /= (0, 0, 0, 32)  --  pubkey length
           or else Bytes (95 .. 98) /= (0, 0, 0, 144)  --  privkey length
           or else Bytes (107 .. 110) /= (0, 0, 0, 11)  --  key type length
           or else Text (111 .. 121) /= "ssh-ed25519"
           or else Bytes (122 .. 125) /= (0, 0, 0, 32)  --  privkey length
           or else Bytes (126 .. 157) /= Bytes (63 .. 94)  --  pubkey match
           or else Bytes (158 .. 161) /= (0, 0, 0, 64)
         then
            Ada.Text_IO.Put_Line ("Not a valid ED25519 private key file!");
            Success := False;
         else
            Value := Bytes (162 .. 193);
            Success := True;
         end if;
      end;
   end Read_ED25519_Key;

   ----------------------
   -- Write_X25519_Key --
   ----------------------

   procedure Write_X25519_Key
     (Name : String;
      Key  : Stream_Element_Array_32)
   is
      Output : Ada.Streams.Stream_IO.File_Type;
      Header : Ada.Streams.Stream_Element_Array (1 .. 16) :=
        (16#30#, 16#2E#, 16#02#, 16#01#, 16#00#, 16#30#, 16#05#, 16#06#,
         16#03#, 16#2B#, 16#65#, 16#6E#, 16#04#, 16#22#, 16#04#, 16#20#);
   begin
      Ada.Streams.Stream_IO.Create
        (File => Output,
         Mode => Ada.Streams.Stream_IO.Out_File,
         Name => Name);
      Ada.Streams.Stream_IO.Write (Output, Header);
      Ada.Streams.Stream_IO.Write (Output, Key);
      Ada.Streams.Stream_IO.Close (Output);
   end Write_X25519_Key;

end Dead_Man_Hand.Decrypt;