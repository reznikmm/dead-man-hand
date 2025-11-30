--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Ada.Text_IO;

with Util.Http.Clients.Curl;

package body Dead_Man_Hand.Fetch is

   function Fetch_User_Data
     (Logger   : Util.Log.Loggers.Logger;
      Username : String;
      Key_Kind : String) return String
   is
      Http     : Util.Http.Clients.Client;
      URI      : constant String :=
        "https://raw.githubusercontent.com/reznikmm/dead-man-hand/aoc/data/"
          & Username & "." & Key_Kind;
      Response : Util.Http.Clients.Response;
   begin
      Logger.Info ("Fetching URL {0}", URI);

      Http.Get (URI, Response);

      Logger.Info
       ("Received response with status: {0}",
        Natural'Image (Response.Get_Status));

      return (if Response.Get_Status = 200 then Response.Get_Body else "");
   end Fetch_User_Data;

begin
   Util.Http.Clients.Curl.Register;
end Dead_Man_Hand.Fetch;