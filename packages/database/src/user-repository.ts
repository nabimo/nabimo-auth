import type { PrismaClient } from "./generated/client.js";

export interface CreateUserInput {
  email?: string;
  phone?: string;
  passwordHash?: string;
}

export class UserRepository {
  constructor(private readonly db: PrismaClient) {}

  findById(id: string) {
    return this.db.user.findUnique({ where: { id } });
  }

  findByEmail(email: string) {
    return this.db.user.findUnique({ where: { email } });
  }

  findByPhone(phone: string) {
    return this.db.user.findUnique({ where: { phone } });
  }

  create(input: CreateUserInput) {
    if (!input.email && !input.phone) {
      throw new Error("User requires an email or phone");
    }

    return this.db.user.create({ data: input });
  }
}
