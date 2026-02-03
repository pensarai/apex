// import { useEffect, useState } from "react";
// import { useKeyboard } from "@opentui/react";
// import { Session } from "../../../core/session";
// import { useFocus } from "../../context/focus";
// import { Dialog } from "../dialog";

// interface CreateSessionDialogProps {
//   onClose: () => void;
//   onSuccess: (sessionId: string) => void;
// }

// export default function CreateSessionDialog({ onClose, onSuccess }: CreateSessionDialogProps) {
//   const { refocusCommandInput } = useFocus();
//   const [name, setName] = useState("");
//   const [error, setError] = useState("");

//   const createSession = async () => {
//       try {
//           const newSession = await Session.create({ name: name.trim() });
//           onSuccess(newSession.id);
//         } catch (err) {
//           setError("Failed to create session");
//           console.error(err);
//         }
//   }

//   // const updateTargets = async () => {
//   //   try {
//   //     if(targets.length > 0) {
//   //       await Session.update(newSessionId, (session) => {
//   //         session.targets = targets;
//   //       });
//   //       onSuccess(newSessionId);
//   //       return;
//   //     }
//   //     setError("Please provide a target endpoint");
//   //     return;
//   //   } catch (err) {
//   //     setError("Failed to create session");
//   //     console.error(err); 
//   //   }
//   // }

//   useKeyboard(async (key) => {
//     // Escape - Close dialog or go back
//     if (key.name === "escape") {
//       refocusCommandInput();
//       onClose();
//       return;
//     }

//     if (key.name === "return") {
//       if (!name.trim()) {
//         setError("Session name is required");
//         return;
//       }
//       setError("");
//       await createSession();
//       return;
//     }

//   });

//   const handleClose = () => {
//     refocusCommandInput();
//     onClose();
//   };

//   return (
//     <Dialog size="medium" onClose={handleClose}>
//       <box
//         flexDirection="column"
//         padding={2}
//         gap={2}
//         width="100%"
//       >
//         {/* Header */}
//         <box flexDirection="row" justifyContent="space-between" width="100%">
//           <text fg="white">
//             Create New Session
//           </text>
//           <text fg="gray">esc to cancel</text>
//         </box>
//             <box
//               width="100%"
//               border={["left"]}
//               borderColor="green"
//               backgroundColor="transparent"
//             >
//               <input
//                 paddingLeft={1}
//                 backgroundColor="transparent"
//                 placeholder="Session name"
//                 value={name}
//                 onInput={setName}
//                 focused
//               />
//             </box>

//             {/* Error Message */}
//             {error && <text fg="red">{error}</text>}

//             {/* Footer */}
//             <box flexDirection="row" gap={2}>
//               <text fg="gray">
//                 <span fg="green">[Enter]</span> Confirm
//               </text>
//             </box>
//       </box>
//     </Dialog>
//   );
// }
