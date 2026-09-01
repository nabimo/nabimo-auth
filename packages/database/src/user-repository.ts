import type { PrismaClient } from "./generated/client.js";

export interface CreateUserInput {
  email?: string;
  phone?: string;
  passwordHash?: string;
}

export class UserRepository {
  constructor(private readonly db: PrismaClient) {}

  findById(id: string) {
    return this.db.user.findUnique({
      where: { id },
      include: { passwordCredential: true },
    });
  }

  findByEmail(email: string) {
    return this.db.user.findUnique({
      where: { email },
      include: { passwordCredential: true },
    });
  }

  findByPhone(phone: string) {
    return this.db.user.findUnique({
      where: { phone },
      include: { passwordCredential: true },
    });
  }

  create(input: CreateUserInput) {
    if (!input.email && !input.phone) {
      throw new Error("User requires an email or phone");
    }

    const { passwordHash, ...userData } = input;
    return this.db.user.create({
      data: {
        ...userData,
        ...(passwordHash
          ? { passwordCredential: { create: { passwordHash } } }
          : {}),
      },
      include: { passwordCredential: true },
    });
  }
}
