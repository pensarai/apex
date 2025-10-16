import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { RGBA } from "@opentui/core";

export default function ResponsibleUseDisclosure({
    onAccept
}:{
    onAccept: () => void
}) {
    const { width } = useTerminalDimensions();
    
    useKeyboard((key) => {
        // Enter key accepts the policy
     if (key.name === "return" || key.name === "enter") {
        onAccept();
     }
    });

    // ASCII art is 127 characters wide - only show if terminal is wide enough
    const showAsciiArt = false;

    return (
    <box
     width="100%"
     height="100%"
     justifyContent="center"
     alignItems="center"
     backgroundColor={"transparent"}
    >
        <box
         flexDirection="column"
         gap={1}
         border={true}
         borderColor={"gray"}
         padding={1}
        >
            <text fg="yellow">IMPORTANT: Read Before Use</text>
            <text fg="white">
            This penetration testing tool is designed for AUTHORIZED security
            testing only.
            </text>
            <box flexDirection="column" marginBottom={1}>
            <text fg="red">
                You MUST have explicit written permission to test any systems,
                networks, or applications
            </text>
            </box>
            <text fg="white">By accepting, you agree to:</text>
            <box flexDirection="column" marginLeft={2}>
            <text>• Only test systems you own or have authorization</text>
            <text fg="white">
                • Comply with all applicable laws and regulations
            </text>
            <text fg="white">• Use this tool ethically and responsibly</text>
            <text fg="white">• Not cause harm or disruption to services</text>
            <text fg="white">• Document and report findings appropriately</text>
            </box>
            <box flexDirection="column">
            <text fg="red">
                Unauthorized access to computer systems is illegal and may result in
                criminal prosecution.
            </text>
            </box>
            <box>
            <text fg="white">
                Press <span fg="green">ENTER</span> to accept and continue
            </text>
            </box>
        </box>
    </box>
    )
}


// <box flexDirection="column" marginBottom={1} alignItems="center">
//             <text fg="cyan">__/\\\\\\\\\\\\\____/\\\\\\\\\\\\\\\__/\\\\\_____/\\\_____/\\\\\\\\\\\_______/\\\\\\\\\_______/\\\\\\\\\_______________</text>
//             <text fg="cyan"> _\/\\\/////////\\\_\/\\\///////////__\/\\\\\\___\/\\\___/\\\/////////\\\___/\\\\\\\\\\\\\___/\\\///////\\\_____________</text>
//             <text fg="cyan">  _\/\\\_______\/\\\_\/\\\_____________\/\\\/\\\__\/\\\__\//\\\______\///___/\\\/////////\\\_\/\\\_____\/\\\_____________</text>
//             <text fg="cyan">   _\/\\\\\\\\\\\\\/__\/\\\\\\\\\\\_____\/\\\//\\\_\/\\\___\////\\\_________\/\\\_______\/\\\_\/\\\\\\\\\\\/______________</text>
//             <text fg="cyan">    _\/\\\/////////____\/\\\///////______\/\\\\//\\\\/\\\______\////\\\______\/\\\\\\\\\\\\\\\_\/\\\//////\\\______________</text>
//             <text fg="cyan">     _\/\\\_____________\/\\\_____________\/\\\_\//\\\/\\\_________\////\\\___\/\\\/////////\\\_\/\\\____\//\\\_____________</text>
//             <text fg="cyan">      _\/\\\_____________\/\\\_____________\/\\\__\//\\\\\\__/\\\______\//\\\__\/\\\_______\/\\\_\/\\\_____\//\\\____________</text>
//             <text fg="cyan">       _\/\\\_____________\/\\\\\\\\\\\\\\\_\/\\\___\//\\\\\_\///\\\\\\\\\\\/___\/\\\_______\/\\\_\/\\\______\//\\\___________</text>
//             <text fg="cyan">        _\///______________\///////////////__\///_____\/////____\///////////_____\///________\///__\///________\///____________</text>
//           </box>