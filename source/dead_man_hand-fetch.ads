--  SPDX-FileCopyrightText: 2025 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
----------------------------------------------------------------

with Util.Log.Loggers;

package Dead_Man_Hand.Fetch is

   function Fetch_User_Data
     (Logger   : Util.Log.Loggers.Logger;
      Username : String;
      Key_Kind : String) return String;

   function Read_File (File_Name : String) return String;

end Dead_Man_Hand.Fetch;