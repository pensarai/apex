import React from "react";
import { RGBA } from "@opentui/core";

/**
 * A box-style logo component that renders the letter "A" using colored block characters
 * in a green gradient style, similar to the Minecraft-style pixel art logo.
 */

// Define the "A" pattern - 1 means filled block, 0 means empty (part of the letter)
// The letter is formed by the empty spaces
const LOGO_PATTERN = [
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1],
  [1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1],
  [1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1],
  [1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1],
  [1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1],
  [1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
];

// Green gradient colors from bright (top) to dark (bottom)
const GREEN_GRADIENT = [
  { r: 144, g: 238, b: 144 }, // Light green
  { r: 124, g: 218, b: 124 },
  { r: 100, g: 200, b: 100 },
  { r: 76, g: 175, b: 80 },   // Medium green
  { r: 56, g: 155, b: 60 },
  { r: 46, g: 125, b: 50 },
  { r: 36, g: 100, b: 40 },
  { r: 27, g: 80, b: 33 },    // Dark green
];

const BLOCK_CHAR = "█";

// BoxLogo is currently disabled - uncomment to use
// export function BoxLogo() {
//   return (
//     <box flexDirection="column" alignItems="center" justifyContent="center">
//       {LOGO_PATTERN.map((row, rowIndex) => {
//         const color = GREEN_GRADIENT[rowIndex] || GREEN_GRADIENT[GREEN_GRADIENT.length - 1];
//         const rgbaColor = RGBA.fromInts(color.r, color.g, color.b, 255);
//
//         return (
//           <text key={rowIndex}>
//             {row.map((cell, colIndex) => {
//               if (cell === 1) {
//                 return (
//                   <span key={colIndex} fg={rgbaColor}>
//                     {BLOCK_CHAR}{BLOCK_CHAR}
//                   </span>
//                 );
//               } else {
//                 return (
//                   <span key={colIndex}>
//                     {"  "}
//                   </span>
//                 );
//               }
//             })}
//           </text>
//         );
//       })}
//     </box>
//   );
// }

export function BoxLogo() {
  return null;
}
