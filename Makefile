NAME		=	infector

UNAME		=	$(shell uname)

ASM			=	nasm
ASMFLAGS	=	-f

CXX			=	gcc
CXXFLAGS	=	-Wall -Wextra -Werror -I $(INCLUDE)

SRCDIR		=	./src
C_SRCDIR	=	$(SRCDIR)/c/
ASM_SRCDIR	=	$(SRCDIR)/asm/
OBJDIR		=	./obj/
INCLUDE		=	./include/
PAYLOADDIR	=	./payloads/

SRC			=	main.c  \
				utils.c \
	            elf64.c
				#elf32.c

PAYLOAD_SRC	=	handler_elf64.s \
				handler_elf32.s \

PAYLOADS	=	${addprefix $(PAYLOADDIR), $(PAYLOAD_SRC:%.s=%.bin)}

OBJ			=	${addprefix $(OBJDIR), $(SRC:%.c=%.o)}


# ===== #


all: $(NAME)

$(NAME): $(OBJDIR) $(OBJ) $(PAYLOADDIR) $(PAYLOADS)
	$(CXX) $(CXXFLAGS) $(OBJ) -o $(NAME)

clean:
	rm -rf $(NAME) $(OBJDIR) $(PAYLOADDIR) patched

re:	clean all

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PAYLOADDIR):
	@mkdir -p $(PAYLOADDIR)

$(OBJDIR)%.o: $(C_SRCDIR)%.c
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(PAYLOADDIR)%.bin: $(ASM_SRCDIR)%.s
	$(ASM) $(ASMFLAGS) bin $< -o $@

.PHONY:					re clean obj all
