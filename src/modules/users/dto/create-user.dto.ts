import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty({ message: 'Username é obrigatório' })
  username!: string;

  @IsEmail({}, { message: 'E-mail inválido' })
  email!: string;

  @MinLength(6, { message: 'Senha precisa ter pelo menos 6 caracteres' })
  password!: string;
}
