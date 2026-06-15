// Command server is the MXID Community Edition entrypoint. It just calls
// app.Run(); all wiring lives in github.com/imkerbos/mxid/app so the EE
// distribution can reuse it (see github.com/imkerbos/mxid-ee).
package main

import "github.com/imkerbos/mxid/app"

func main() {
	app.Run()
}
