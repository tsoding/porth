;;; porth-mode.el --- Major Mode for editing Porth source code -*- lexical-binding: t -*-

;; Copyright (C) 2021 Alexey Kutepov <reximkut@gmail.com>

;; Author: Alexey Kutepov <reximkut@gmail.com>
;; URL: https://github.com/tsoding/porth

;; Permission is hereby granted, free of charge, to any person
;; obtaining a copy of this software and associated documentation
;; files (the "Software"), to deal in the Software without
;; restriction, including without limitation the rights to use, copy,
;; modify, merge, publish, distribute, sublicense, and/or sell copies
;; of the Software, and to permit persons to whom the Software is
;; furnished to do so, subject to the following conditions:

;; The above copyright notice and this permission notice shall be
;; included in all copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
;; BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
;; ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;; SOFTWARE.

;;; Commentary:
;;
;; Major Mode for editing Porth source code. It's Forth but written in Python.

(defconst porth-mode-syntax-table
  (with-syntax-table (copy-syntax-table)
    ;; C/C++ style comments
	(modify-syntax-entry ?/ ". 124b")
	(modify-syntax-entry ?* ". 23")
	(modify-syntax-entry ?\n "> b")
    ;; Chars are the same as strings
    (modify-syntax-entry ?' "\"")
    (syntax-table))
  "Syntax table for `porth-mode'.")

(eval-and-compile
  (defconst porth-keywords
    '("if" "elif" "else" "end" "while" "do" "macro" "include")))

(defconst porth-highlights
  `((,(regexp-opt porth-keywords 'symbols) . font-lock-keyword-face)))

;;;###autoload
(define-derived-mode porth-mode prog-mode "porth"
  "Major Mode for editing Porth source code."
  (setq font-lock-defaults '(porth-highlights))
  (set-syntax-table porth-mode-syntax-table))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.porth\\'" . porth-mode))

(provide 'porth-mode)

;;; porth-mode.el ends here
