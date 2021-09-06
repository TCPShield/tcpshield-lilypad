package main

import (
	"fmt"
	"github.com/LilyPad/GoLilyPad/packet/minecraft"
	"github.com/LilyPad/GoLilyPad/server/proxy/api"
)

var Plugin TCPShieldPlugin

type TCPShieldPlugin string

func (plugin *TCPShieldPlugin) Init(context api.Context) {
	fmt.Println("Enabling TCPShield Plugin")

	context.EventBus().HandleSessionPacket(func(eventSession api.EventSession) {
		event, ok := eventSession.(api.EventSessionPacket)
		if !ok {
			fmt.Println("Failed to process HandleSessionPacket, event is invalid type")
			return
		}

		packet := event.Packet()
		packetHandshake, ok := packet.(*minecraft.PacketServerHandshake)
		if !ok {
			fmt.Println("Failed to process HandleSessionPacket, event.Packet() is invalid type")
			return
		}

		session := event.Session()
		playerIP, playerPort := session.Remote()
		if err := Verify(packetHandshake.ServerAddress, &playerIP); err != nil {
			playerName, uuid := session.Profile()
			fmt.Println("Failed to verify TCPShield session for player:", playerName, uuid, "error:", err.Error())
			session.Disconnect("Failed to verify session")
			event.SetCancelled(true)
			return
		}

		session.RemoteOverride(playerIP, playerPort)
	}, api.PacketStagePre, api.PacketSubjectClient, api.PacketDirectionRead, api.SessionStateDisconnected)
}
