import axios from "axios";

export async function listInvoices() {
  return axios.get("/api/billing/invoices");
}

export async function loadInvoice(invoiceId: string) {
  return axios.get(`/api/billing/invoices/${invoiceId}`);
}
