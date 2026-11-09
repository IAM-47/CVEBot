package bot

const (
	HintMessage            = "Wrong format! Format should be like \"/command <any tech> [version]\""
	BadNetworkMessage      = "Something went wrong. Please try again later."
	EmptyRespMessage       = "Nothing was found for your request."
	TooShortQuery          = "Sorry but your request is too short."
	DBError                = "Something went wrong. Please try again later."
	SuccessfulSubscription = "Subscribed successfully!"
	HelpMessage            = "– /cve <tech> [version]\n" +
		"– /subscribe <tech> [version] [low | medium | high | critical] [kev]\n" +
		"– /unsubscribe <tech> [version]\n" +
		"– /list\n" +
		"– /help"
	StartMessage        = "Hey! Just send me any of these commands:\n" + HelpMessage
	AlreadySubscribed   = "Already subscribed!"
	EmptyList           = "You have no subscriptions. To subscribe type: /subscribe <tech> [version]"
	DeletedSuccessfully = "Deleted successfully!"
	NoSuchSubscription  = "No such subscription!"
)
