import type { PrismaClient, User } from "../generated/client.js";

export interface CreateUserInput {
  email?: string;
  phone?: string;
  passwordHash?: string;
}

export class UserRepository {
  constructor(private readonly db: PrismaClient) {}

  findById(id: string): Promise<User | null> {
    return this.db.user.findUnique({ where: { id } });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.db.user.findUnique({ where: { email } });
  }

  findByPhone(phone: string): Promise<User | null> {
    return this.db.user.findUnique({ where: { phone } });
  }

  create(input: CreateUserInput): Promise<User> {
    return this.db.user.create({ data: input });
  }
}
