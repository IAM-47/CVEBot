package main

const (
	HintMessage            = "Wrong format! Format should be like \"/command <any tech> [version]\""
	BedNetworkMessage      = "Something went wrong. Please try again later."
	EmptyRespMessage       = "Nothing was found for your request."
	TooShortQuery          = "Sorry but your request is too short."
	DBError                = "Something went wrong. Please try again later."
	SuccessfulSubscription = "Subscribed successfully!"
	HelpMessage            = "– /cve <tech> [version]>\n" +
		"– /subscribe <tech> [version]>\n" +
		"– /help"
	StartMessage      = "Hey! Just send me any of these commands:\n" + HelpMessage
	AlreadySubscribed = "Already subscribed!"
)
