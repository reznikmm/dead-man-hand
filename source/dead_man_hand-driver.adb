--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

pragma Ada_2012;

with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Text_IO;

with Util.Log.Loggers;
with Util.Properties;

with Dead_Man_Hand.Fetch;
with Dead_Man_Hand.Decrypt;

procedure Dead_Man_Hand.Driver is
   procedure Initialize_Logger;

   function Argument_Index (Text : String) return Natural;

   --------------------
   -- Argument_Index --
   --------------------

   function Argument_Index (Text : String) return Natural is
   begin
      for J in 1 .. Ada.Command_Line.Argument_Count - 1 loop
         if Ada.Command_Line.Argument (J) = Text then
            return J;
         end if;
      end loop;
      return 0;
   end Argument_Index;


   procedure Initialize_Logger is
   begin
      if Argument_Index ("--verbose") > 0 then
         declare
            Properties : Util.Properties.Manager;
            --  log4j.rootCategory=INFO,result
            --  log4j.appender.result=Console
            --  log4j.appender.result.layout=level-message
            --  log4j.logger.driver=INFO
         begin
            Properties.Set ("log4j.rootCategory", "INFO,result");
            Properties.Set ("log4j.appender.result", "Console");
            Properties.Set ("log4j.appender.result.layout", "level-message");
            Properties.Set ("log4j.logger.driver", "INFO");

            Util.Log.Loggers.Initialize (Properties);
         end;
      end if;
   end Initialize_Logger;

   function SSH_Dir return String is
     (Ada.Environment_Variables.Value
       ("HOME",
        Default => Ada.Environment_Variables.Value ("USERPROFILE", ""))
      & "/.ssh/");

   function RSA_Key return String is
     (if Argument_Index ("--rsa-key") = 0 then SSH_Dir & "id_rsa"
      else
        Ada.Command_Line.Argument (Argument_Index ("--rsa-key") + 1));

   function ED25519_Key return String is
     (if Argument_Index ("--ed25519-key") = 0 then SSH_Dir & "id_ed25519"
      else
        Ada.Command_Line.Argument (Argument_Index ("--ed25519-key") + 1));

begin
   if Ada.Command_Line.Argument_Count < 1 then
      Ada.Text_IO.Put_Line
        ("Usage: dead_man_hand [options] <github-username>");

      Ada.Text_IO.Put_Line ("Options:");

      Ada.Text_IO.Put_Line
        ("  --rsa-key <path>     Path to RSA private key" &
         " (default: ~/.ssh/id_rsa)");

      Ada.Text_IO.Put_Line
        ("  --ed25519-key <path> Path to ED25519 private key" &
         " (default: ~/.ssh/id_ed25519)");

      Ada.Text_IO.Put_Line
        ("  --rsa-file <path>    Path to local RSA encrypted file");

      Ada.Text_IO.Put_Line
        ("  --ed-file <path>     Path to local ED25519 encrypted file");

      Ada.Text_IO.Put_Line
        ("  --verbose            Enable verbose logging");
      return;
   else
      declare
         Logger : constant Util.Log.Loggers.Logger :=
           Util.Log.Loggers.Create ("driver");

         Username : constant String :=
           Ada.Command_Line.Argument (Ada.Command_Line.Argument_Count);
      begin
         Initialize_Logger;

         declare
            RSA_Text : constant String :=
              (if Argument_Index ("--rsa-file") = 0
               then Dead_Man_Hand.Fetch.Fetch_User_Data
                 (Logger, Username, "rsa")
               else Dead_Man_Hand.Fetch.Read_File
                 (Ada.Command_Line.Argument
                   (Argument_Index ("--rsa-file") + 1)));

            ED_Text : constant String :=
              (if Argument_Index ("--ed-file") = 0
               then Dead_Man_Hand.Fetch.Fetch_User_Data
                 (Logger, Username, "ed25519")
               else Dead_Man_Hand.Fetch.Read_File
                 (Ada.Command_Line.Argument
                   (Argument_Index ("--ed-file") + 1)));
         begin
            if RSA_Text = "" and then ED_Text = "" then
               Ada.Text_IO.Put_Line ("No data found for user " & Username);
            end if;

            if RSA_Text /= "" then
               Dead_Man_Hand.Decrypt.Decrypt_RSA (Logger, RSA_Key, RSA_Text);
            end if;

            if ED_Text /= "" then
               Dead_Man_Hand.Decrypt.Decrypt_ED25519
                (Logger, ED25519_Key, ED_Text);
            end if;
         end;
      end;
   end if;
end Dead_Man_Hand.Driver;
