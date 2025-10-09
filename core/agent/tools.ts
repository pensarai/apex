import { tool } from "ai";
import z from "zod";

const curlTool = tool({
  name: "curl",
  description: "Curl a URL",
  inputSchema: z.object({
    url: z.string(),
  }),
});
