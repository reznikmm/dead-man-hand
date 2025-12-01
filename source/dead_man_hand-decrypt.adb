--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Ada.Characters.Latin_1;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Directories;

with GNAT.OS_Lib;
with GNAT.SHA512;

with Util.Encoders.AES;
with Util.Encoders.HMAC.SHA256;
with Util.Encoders.SHA256;
with Util.Files;
with Util.Processes;
with Util.Streams.Buffered;
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

   procedure Write_X25519_Private_Key
     (Name : String;
      Key  : Stream_Element_Array_32);

   procedure Write_X25519_Public_Key
     (Name : String;
      Key  : Stream_Element_Array_32);

   procedure Derive_Shared_Key
     (Logger      : Util.Log.Loggers.Logger;
      Private_Key : Stream_Element_Array_32;
      Public_Key  : Stream_Element_Array_32;
      Hex         : out String);

   procedure HKDF_Derive_Keys
     (Logger     : Util.Log.Loggers.Logger;
      Shared_Key : String;
      AES_Key    : out Stream_Element_Array_32;
      HMAC_Key   : out Stream_Element_Array_32);

   function Is_OpenSSH_Private_Key
     (Logger : Util.Log.Loggers.Logger;
      Key    : String) return Boolean;

   procedure Copy_Key_File (Key : String);

   -------------------
   -- Copy_Key_File --
   -------------------

   procedure Copy_Key_File (Key : String) is
   begin
      declare
         use type GNAT.OS_Lib.String_Access;

         Ok        : Boolean;
         CP        : constant GNAT.OS_Lib.String_Access :=
           GNAT.OS_Lib.Locate_Exec_On_Path ("cp");
         K         : aliased String := Key;
         P         : aliased String := "-p";
         V         : aliased String := "-v";
         Temp      : aliased String := "temp";
         Arguments : constant GNAT.OS_Lib.Argument_List :=
           (P'Unchecked_Access,
            V'Unchecked_Access,
            K'Unchecked_Access,
            Temp'Unchecked_Access);
      begin
         if CP = null or else CP.all = "" then
            Ada.Text_IO.Put_Line ("Can't find 'cp' command in PATH!");
         else
            GNAT.OS_Lib.Spawn
              (Program_Name => CP.all, Args => Arguments, Success => Ok);
         end if;
      end;
   end Copy_Key_File;

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

      procedure Remove_Password_And_Read;

      ------------------------------
      -- Remove_Password_And_Read --
      ------------------------------

      procedure Remove_Password_And_Read is
         Pipe  : aliased Util.Streams.Pipes.Pipe_Stream;

      begin
         Ada.Text_IO.Put_Line
           ("Private key seems to be password-protected.");
         Ada.Text_IO.Put_Line
           ("I'm going to copy it and run 'ssh-keygen -p' to remove the" &
            " password. I'll delete the temporary file afterwards.");

         Copy_Key_File (Key);

         Ada.Text_IO.Put_Line ("Starting 'ssh-keygen -p'");
         Ada.Text_IO.Put_Line ("It should ask for your private key password!");

         Pipe.Open
           (Command => "ssh-keygen -p -f temp -N ''",
            Mode => Util.Processes.READ);

         Pipe.Close;

         Logger.Info
           ("Command exited with status {0}",
            Integer'Image (Pipe.Get_Exit_Status));

         if Pipe.Get_Exit_Status = 0 then
            Logger.Info ("Decryption with 'ssh-keygen -p' successful!");
            Read_ED25519_Key (Logger, "temp", Private_Key, Success);
            Ada.Directories.Delete_File ("temp");
         else
            Ada.Text_IO.Put_Line ("Unable to remove password from key!");
            Ada.Text_IO.Put_Line ("Please execute:");
            Ada.Text_IO.Put_Line ("  ssh-keygen -p -f <keyfile> -N ''");
            Ada.Text_IO.Put_Line ("And restart with --ed25519-key <keyfile>");
         end if;
      end Remove_Password_And_Read;

      Bytes : constant Ada.Streams.Stream_Element_Array :=
        Decode_Base64 (Logger, Text);

      Shared_Key : String (1 .. 64);  --  hex-encoded shared key

      AES_Key : Stream_Element_Array_32;
      HMAC_Key : Stream_Element_Array_32;

      function Public_Bytes return Stream_Element_Array_32 is
        (Bytes (1 .. 32));

      function IV return Ada.Streams.Stream_Element_Array is
        (Bytes (33 .. 48));

      function HMAC_Tag_Received return Ada.Streams.Stream_Element_Array is
        (Bytes (49 .. 80));

      function Payload return Ada.Streams.Stream_Element_Array is
        (Bytes (81 .. Bytes'Length));

   begin
      if not Ada.Directories.Exists (Key) then
         Ada.Text_IO.Put_Line
           ("Can't find private key file " & Key & " does not exist!");

         return;
      end if;

      Read_ED25519_Key (Logger, Key, Private_Key, Success);

      if not Success then
         Remove_Password_And_Read;
      end if;

      if not Success then
         return;
      end if;

      ED25519_To_X25519 (Private_Key);
      Derive_Shared_Key (Logger, Private_Key, Public_Bytes, Shared_Key);
      HKDF_Derive_Keys (Logger, Shared_Key, AES_Key, HMAC_Key);
      --  Check HMAC
      declare
         use type Util.Encoders.SHA256.Hash_Array;
         Context : Util.Encoders.HMAC.SHA256.Context;
         Hash    : Util.Encoders.SHA256.Hash_Array;
      begin
         Util.Encoders.HMAC.SHA256.Set_Key (Context, HMAC_Key);
         Util.Encoders.HMAC.SHA256.Update (Context, Public_Bytes);
         Util.Encoders.HMAC.SHA256.Update (Context, IV);
         Util.Encoders.HMAC.SHA256.Update (Context, Payload);
         Util.Encoders.HMAC.SHA256.Finish (Context, Hash);
         Success := Hash = HMAC_Tag_Received;

         Logger.Info
           ("HMAC verification {0}",
            (if Success then "succeeded" else "failed"));
      end;

      if not Success then
         Ada.Text_IO.Put_Line ("Decryption failed!");
         return;
      end if;

      --  Decrypt with AES-CBC
      declare
         use type Ada.Streams.Stream_Element_Offset;
         Key      : Util.Encoders.Secret_Key (Length => 32);
         IV_Key   : Util.Encoders.Secret_Key (Length => 16);
         Decoder  : Util.Encoders.AES.Decoder;
         Result   : Ada.Streams.Stream_Element_Array (Payload'Range);
         Last     : Ada.Streams.Stream_Element_Offset;
         Encoded  : Ada.Streams.Stream_Element_Offset;
         Output   : Ada.Streams.Stream_IO.File_Type;
      begin
         Util.Encoders.Create (AES_Key, Key);
         Util.Encoders.Create (IV, IV_Key);
         Decoder.Set_Key (Key, Util.Encoders.AES.CBC);
         Decoder.Set_IV (IV_Key);
         Decoder.Set_Padding (Util.Encoders.AES.PKCS7_PADDING);
         Decoder.Transform (Payload, Result, Last, Encoded);
         Decoder.Finish (Result (Last + 1 .. Result'Last), Last);

         Logger.Info
           ("Decrypted {0} bytes with AES-CBC",
            Ada.Streams.Stream_Element_Offset'Image (Last));

         Ada.Streams.Stream_IO.Create
           (File => Output,
            Mode => Ada.Streams.Stream_IO.Out_File,
            Name => "result-ed.txt");
         Ada.Streams.Stream_IO.Write (Output, Result (Result'First .. Last));
         Ada.Streams.Stream_IO.Close (Output);

         Ada.Text_IO.Put_Line ("Decryption successful! See 'result-ed.txt'");
         Ada.Text_IO.New_Line;
      end;
   end Decrypt_ED25519;

   -----------------
   -- Decrypt_RSA --
   -----------------

   procedure Decrypt_RSA
     (Logger   : Util.Log.Loggers.Logger;
      Key      : String;
      Text     : String)
   is
      Pipe  : aliased Util.Streams.Pipes.Pipe_Stream;
      Bytes : constant Ada.Streams.Stream_Element_Array :=
        Decode_Base64 (Logger, Text);
   begin
      if not Ada.Directories.Exists (Key) then
         Ada.Text_IO.Put_Line
           ("Can't find private key file " & Key & " does not exist!");

         return;
      elsif Is_OpenSSH_Private_Key (Logger, Key) then
         Ada.Text_IO.Put_Line
           ("The private key file " & Key & " is not in PEM format!");
         Ada.Text_IO.Put_Line
           ("I make a temporary copy of your key file into './temp'");

         Copy_Key_File (Key);

         declare
            Pipe : aliased Util.Streams.Pipes.Pipe_Stream;
         begin
            Ada.Text_IO.Put_Line ("Now let's turn ./temp into PEM format.");
            Ada.Text_IO.Put_Line ("  ssh-keygen -p -f temp -m PEM");

            Pipe.Open
              (Command => "ssh-keygen -p -f temp -m PEM",
               Mode => Util.Processes.READ);

            Pipe.Close;

            if Pipe.Get_Exit_Status = 0 then
               Ada.Text_IO.Put_Line ("Conversion to PEM successful!");
               Decrypt_RSA (Logger, "temp", Text);
               return;
            else
               Ada.Text_IO.Put_Line ("Conversion to PEM failed!");
            end if;
         end;
      end if;

      Ada.Text_IO.Put_Line ("Starting 'openssl pkeyutl -decrypt'");
      Ada.Text_IO.Put_Line ("It may ask for your private key passphrase!");

      Pipe.Open
        (Command =>
          "openssl pkeyutl -decrypt -inkey """ &
           Key &
           """ -pkeyopt rsa_padding_mode:oaep" &
           " -pkeyopt rsa_oaep_md:sha256" &
           " -pkeyopt rsa_mgf1_md:sha256" &
           " -out result-rsa.txt",
         Mode => Util.Processes.WRITE);
      Pipe.Write (Bytes);
      Pipe.Flush;
      Pipe.Close;

      Logger.Info
        ("Command exited with status {0}",
         Integer'Image (Pipe.Get_Exit_Status));

      if Pipe.Get_Exit_Status = 0 then
         Ada.Text_IO.Put_Line ("Decryption successful! See 'result-rsa.txt'");
         Ada.Text_IO.New_Line;
      else
         Ada.Text_IO.Put_Line ("Decryption failed!");
         Ada.Text_IO.New_Line;
         Ada.Text_IO.Put_Line ("Make sure your RSA key in PEM format.");
         Ada.Text_IO.Put_Line ("Please execute:");
         Ada.Text_IO.Put_Line ("  ssh-keygen -p -f <keyfile> -m PEM");
         Ada.Text_IO.Put_Line ("And restart with --rsa-key <keyfile>");
      end if;
   end Decrypt_RSA;

   -----------------------
   -- Derive_Shared_Key --
   -----------------------

   procedure Derive_Shared_Key
     (Logger      : Util.Log.Loggers.Logger;
      Private_Key : Stream_Element_Array_32;
      Public_Key  : Stream_Element_Array_32;
      Hex         : out String)
   is
      Pipe  : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer : Util.Streams.Buffered.Input_Buffer_Stream;
      Char : Character;
   begin
      Write_X25519_Private_Key ("priv.der", Private_Key);
      Write_X25519_Public_Key ("pub.der", Public_Key);

      --  Run:
      --  openssl pkeyutl -derive -inkey priv.der -peerkey pub.der -hexdump
      Pipe.Open
        (Command =>
           "openssl pkeyutl -derive -inkey priv.der -peerkey pub.der -hexdump",
         Mode => Util.Processes.READ);
      Buffer.Initialize (Input => Pipe'Unchecked_Access, Size => 200);
      Buffer.Fill;

      --  Parse hex dump:
      --  0000 - 11 22 ... FF   1234567890ABCDEF \n
      --  0010 - 11 22 ... FF   1234567890ABCDEF \n
      --

      for J in Hex'Range loop
         if J = 33 then
            --  Skip till ASCII and of line
            loop
               Buffer.Read (Char);
               exit when Char = Ada.Characters.Latin_1.LF;
            end loop;
         end if;
         if J in 1 | 33 then
            --  Skip address offset and a dash
            loop
               Buffer.Read (Char);
               exit when Char = '-';
            end loop;
         end if;
         if J mod 2 = 1 then
            --  Skip space separators
            Buffer.Read (Char);
            pragma Assert (Char in ' ' | '-');
         end if;
         Buffer.Read (Hex (J));
      end loop;

      Logger.Info ("Derived shared key: {0}", Hex);
      Ada.Directories.Delete_File ("priv.der");
      Ada.Directories.Delete_File ("pub.der");
   end Derive_Shared_Key;

   -----------------------
   -- ED25519_To_X25519 --
   -----------------------

   procedure ED25519_To_X25519 (Key : in out Stream_Element_Array_32) is
      use type Ada.Streams.Stream_Element;
   begin
      --  Hash the key with SHA-512
      Key := GNAT.SHA512.Digest (Key) (1 .. 32);
      --  Clamp the key
      Key (1) := Key (1) and 16#F8#;
      Key (32) := (Key (32) and 16#7F#) or 16#40#;
   end ED25519_To_X25519;

   ----------------------
   -- HKDF_Derive_Keys --
   ----------------------

   procedure HKDF_Derive_Keys
     (Logger     : Util.Log.Loggers.Logger;
      Shared_Key : String;
      AES_Key    : out Stream_Element_Array_32;
      HMAC_Key   : out Stream_Element_Array_32)
   is
      Pipe    : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer  : Util.Streams.Buffered.Input_Buffer_Stream;
      Char    : Character;
      Hex_Key : String (1 .. 128);
      Raw     : Ada.Streams.Stream_Element_Array (1 .. 64);

      Decoder : constant Util.Encoders.Decoder :=
        Util.Encoders.Create ("hex");
   begin
      --  Run:
      --  openssl kdf -keylen 64 -kdfopt digest:SHA256
      --    -kdfopt hexkey:SHAREDKEY -kdfopt info:sealed-box-cbc-protocol HKDF
      Pipe.Open
        (Command =>
           "openssl kdf -keylen 64 -kdfopt digest:SHA256 "
           & "-kdfopt hexkey:" & Shared_Key & " "
           & "-kdfopt info:sealed-box-cbc-protocol HKDF",
         Mode => Util.Processes.READ);

      Buffer.Initialize (Input => Pipe'Unchecked_Access, Size => 200);
      Buffer.Fill;

      for J in Hex_Key'Range loop
         if J mod 2 = 1 and then J > 1 then
            --  Skip ':' separators
            Buffer.Read (Char);
            pragma Assert (Char = ':');
         end if;
         Buffer.Read (Hex_Key (J));
      end loop;

      Logger.Info ("Derived HKDF key: {0}", Hex_Key);

      Raw := Decoder.Decode_Binary (Hex_Key);
      AES_Key := Raw (1 .. 32);
      HMAC_Key := Raw (33 .. 64);
   end HKDF_Derive_Keys;

   ----------------------------
   -- Is_OpenSSH_Private_Key --
   ----------------------------

   function Is_OpenSSH_Private_Key
     (Logger : Util.Log.Loggers.Logger;
      Key    : String) return Boolean
   is
      Input : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open
        (File => Input,
         Mode => Ada.Text_IO.In_File,
         Name => Key);

      declare
         Line : constant String := Ada.Text_IO.Get_Line (Input);
      begin
         Ada.Text_IO.Close (Input);

         Logger.Info
           ("First line of key file: {0}",
            Line);

         return Line =
           "-----BEGIN OPENSSH PRIVATE KEY-----";
      end;
   end Is_OpenSSH_Private_Key;

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

   ------------------------------
   -- Write_X25519_Private_Key --
   ------------------------------

   procedure Write_X25519_Private_Key
     (Name : String;
      Key  : Stream_Element_Array_32)
   is
      Output : Ada.Streams.Stream_IO.File_Type;
      Header : constant Ada.Streams.Stream_Element_Array (1 .. 16) :=
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
   end Write_X25519_Private_Key;

   -----------------------------
   -- Write_X25519_Public_Key --
   -----------------------------

   procedure Write_X25519_Public_Key
     (Name : String;
      Key  : Stream_Element_Array_32)
   is
      Output : Ada.Streams.Stream_IO.File_Type;
      Header : constant Ada.Streams.Stream_Element_Array (1 .. 12) :=
        (16#30#, 16#2A#, 16#30#, 16#05#, 16#06#, 16#03#,
         16#2B#, 16#65#, 16#6E#, 16#03#, 16#21#, 16#00#);
   begin
      Ada.Streams.Stream_IO.Create
        (File => Output,
         Mode => Ada.Streams.Stream_IO.Out_File,
         Name => Name);
      Ada.Streams.Stream_IO.Write (Output, Header);
      Ada.Streams.Stream_IO.Write (Output, Key);
      Ada.Streams.Stream_IO.Close (Output);
   end Write_X25519_Public_Key;

end Dead_Man_Hand.Decrypt;
