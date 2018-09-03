rule Catalites
{
    strings:
	  $ = "money_was_add"  nocase
	  $ = "adm_win"  nocase
	  $ = "chat_interface"  nocase
	  $ = "chat_receive"  nocase
	  $ = "chat_sent"  nocase
	  $ = "chat_row" nocase
	  $ = "database.db" nocase
	
	condition:
		all of them

}
