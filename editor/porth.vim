" Vim syntax file
" Language: Porth

" Usage Instructions
" Put this file in .vim/syntax/porth.vim
" and add in your .vimrc file the next line:
" autocmd BufRead,BufNewFile *.porth set filetype=porth

if exists("b:current_syntax")
  finish
endif

syntax keyword porthTodos TODO XXX FIXME NOTE

" Language keywords
syntax keyword porthKeywords if orelse else while do macro include memory proc const end offset reset

" Comments
syntax region porthCommentLine start="//" end="$"   contains=porthTodos

" Strings
syntax region porthString start=/\v"/ skip=/\v\\./ end=/\v"/
syntax region porthString start=/\v'/ skip=/\v\\./ end=/\v'/

" Set highlights
highlight default link porthTodos Todo
highlight default link porthKeywords Keyword
highlight default link porthCommentLine Comment
highlight default link porthString String

let b:current_syntax = "porth"
