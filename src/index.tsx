import { render } from "@opentui/react";
import { convertImageToColoredAscii, ColoredAsciiArt } from "./ascii-art";
import { useState } from "react";
import Header from "./header";
import Footer from "./footer";
import Input from "./input";

// Configuration
const CONFIG = {
  imagePath: "./pensar.svg",
  scale: 1.0, // Scale the image (0.5 = 50%, 1.0 = 100%, 2.0 = 200%)
  maxWidth: 50, // Optional: maximum width in characters (undefined = no limit)
  aspectRatio: 0.5, // Height adjustment (0.5 = half height, good for most terminals)
  invert: true, // Invert brightness (try true if image looks wrong)
  title: "Pensar Logo", // Optional: title to display
};

// Scale the image with sharp first, then convert to ASCII
const coloredAscii = await convertImageToColoredAscii(
  CONFIG.imagePath,
  CONFIG.scale,
  CONFIG.maxWidth,
  CONFIG.aspectRatio,
  CONFIG.invert
);

console.log(
  `Generated colored ASCII: ${coloredAscii.length} rows x ${
    coloredAscii[0]?.length || 0
  } columns (scale: ${CONFIG.scale * 100}%)`
);

function App() {
  const [command, setCommand] = useState("");

  const handleSubmit = (value: string) => {
    console.log("Command submitted:", value);
    // Handle the command here
    setCommand("");
  };

  return (
    <box flexDirection="column" alignItems="center" flexGrow={1} gap={1}>
      <ColoredAsciiArt ascii={coloredAscii} />
      <Header />
      <box
        flexDirection="column"
        justifyContent="center"
        width={60}
        flexGrow={1}
        gap={2}
      >
        <Input label="Target" value={command} placeholder="Enter a url..." />
        <Input
          label="Objective"
          value={command}
          placeholder="Enter an objective..."
        />
        <Input
          label="Command"
          value={command}
          placeholder="Enter a command..."
        />
      </box>
      <Footer />
    </box>
  );
}

render(<App />);
