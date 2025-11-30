--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Text_IO;

with Util.Log.Loggers;
with Util.Properties;

with Dead_Man_Hand.Fetch;
with Dead_Man_Hand.Decrypt;

procedure Dead_Man_Hand.Driver is
   procedure Initialize_Logger;

   procedure Initialize_Logger is
   begin
      if Ada.Command_Line.Argument (1) = "--verbose" then
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

begin
   if Ada.Command_Line.Argument_Count < 1 then
      Ada.Text_IO.Put_Line
        ("Usage: dead_man_hand [--verbose] <github-username>");
      return;
   else
      declare
         Logger : constant Util.Log.Loggers.Logger :=
           Util.Log.Loggers.Create ("driver");

         Username : constant String :=
           Ada.Command_Line.Argument (Ada.Command_Line.Argument_Count);
      begin
         Initialize_Logger;
         Util.Log.Loggers.Initialize ("config.properties");

         declare
            RSA_Text : constant String := Dead_Man_Hand.Fetch.Fetch_User_Data
              (Logger, Username, "rsa");

            ED_Text : constant String := Dead_Man_Hand.Fetch.Fetch_User_Data
              (Logger, Username, "ed25519");
         begin
            if RSA_Text = "" and then ED_Text = "" then
               Ada.Text_IO.Put_Line ("No data found for user " & Username);
            elsif RSA_Text /= "" then
               Dead_Man_Hand.Decrypt.Decrypt_RSA
                (Logger, SSH_Dir & "id_rsa", RSA_Text);
            end if;
         end;
      end;
   end if;
end Dead_Man_Hand.Driver;