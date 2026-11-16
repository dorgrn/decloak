//go:build js && wasm

// Command decloak-wasm exposes the scanner to the browser demo as
// decloakScan(filename, text) -> JSON string. Text never leaves the page.
package main

import (
	"syscall/js"

	"github.com/dorgrn/decloak/internal/scan"
)

func main() {
	js.Global().Set("decloakScan", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 2 {
			return `{"error":"usage: decloakScan(filename, text)"}`
		}
		return scan.JSON(args[0].String(), args[1].String())
	}))
	js.Global().Set("decloakReady", true)
	select {}
}
