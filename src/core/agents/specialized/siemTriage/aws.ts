import { z } from "zod";

export const AwsInvestigationQuery = z.strictObject({
  accountId: z.string().regex(/^\d{12}$/),
  region: z.string().min(1).max(40),
  lookup: z.enum([
    "SecurityGroupId",
    "EventId",
    "EventName",
    "Username",
    "ResourceName",
  ]),
  value: z.string().min(1).max(256),
});

export interface SiemAwsInvestigation {
  accounts: { accountId: string; regions: string[] }[];
  inspect(query: z.infer<typeof AwsInvestigationQuery>): Promise<unknown>;
}
